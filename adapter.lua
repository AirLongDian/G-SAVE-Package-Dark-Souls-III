local PROCESS_NAME = "DarkSoulsIII.exe"
local STEAM_APP_ID = 374320
local EXECUTABLE_RELATIVE_PATH = "Game/DarkSoulsIII.exe"
local DS3_AES_KEY = string.char(
    0xFD, 0x46, 0x4D, 0x69, 0x5E, 0x69, 0xA3, 0x9A,
    0x10, 0xE3, 0x19, 0xA7, 0xAC, 0xE8, 0xB7, 0xFA)
local BND4_HEADER_SIZE = 64
local BND4_ENTRY_HEADER_SIZE = 32
local CHARACTER_SLOT_COUNT = 10
local MENU_ENTRY_INDEX = 10
local MENU_OCCUPANCY_OFFSET = 0x1098
local MENU_PROFILE_OFFSET = 0x10A2
local MENU_PROFILE_STRIDE = 0x22A
local PROFILE_NAME_BYTES = 32
local MAX_MENU_ENTRY_SIZE = 2 * 1024 * 1024

local function problem(code, message)
    return { code = code, message = message }
end

local function normalize_relative(path)
    return path:gsub("\\", "/")
end

local function is_account_name(name)
    return name:match("^[0-9a-fA-F]+$") ~= nil
end

local function u32le(bytes, offset)
    if #bytes < offset + 3 then
        return nil
    end
    local a, b, c, d = bytes:byte(offset, offset + 3)
    return a | (b << 8) | (c << 16) | (d << 24)
end

local function u64le(bytes, offset)
    if #bytes < offset + 7 then
        return nil
    end
    local low = u32le(bytes, offset)
    local high = u32le(bytes, offset + 4)
    return low | (high << 32)
end

local function utf16le_name(bytes, offset, byte_length)
    local result = {}
    local limit = offset + byte_length - 1
    local cursor = offset
    while cursor + 1 <= limit do
        local low, high = bytes:byte(cursor, cursor + 1)
        local codepoint = low | (high << 8)
        if codepoint == 0 then
            break
        end
        if codepoint >= 0xD800 and codepoint <= 0xDBFF and cursor + 3 <= limit then
            local next_low, next_high = bytes:byte(cursor + 2, cursor + 3)
            local next_codepoint = next_low | (next_high << 8)
            if next_codepoint >= 0xDC00 and next_codepoint <= 0xDFFF then
                codepoint = 0x10000 + ((codepoint - 0xD800) << 10)
                    + (next_codepoint - 0xDC00)
                cursor = cursor + 2
            else
                return nil
            end
        elseif codepoint >= 0xDC00 and codepoint <= 0xDFFF then
            return nil
        end
        result[#result + 1] = utf8.char(codepoint)
        cursor = cursor + 2
    end
    return table.concat(result)
end

local function strip_pkcs7(bytes)
    if #bytes == 0 then
        return nil
    end
    local padding = bytes:byte(#bytes)
    if padding == 0 or padding > 16 or padding > #bytes then
        return nil
    end
    for index = #bytes - padding + 1, #bytes do
        if bytes:byte(index) ~= padding then
            return nil
        end
    end
    return bytes:sub(1, #bytes - padding)
end

local function parse_slots(repository, path, header, file_size, warnings)
    local entry_count = u32le(header, 13)
    if entry_count == nil or entry_count <= MENU_ENTRY_INDEX then
        warnings[#warnings + 1] = {
            code = "missing_menu_entry",
            path = path,
            message = "BND4 缺少 USER_DATA_010，无法读取角色槽位",
        }
        return nil, nil
    end

    local entry_header_offset = BND4_HEADER_SIZE
        + MENU_ENTRY_INDEX * BND4_ENTRY_HEADER_SIZE
    local entry_header = repository:read(path, entry_header_offset, BND4_ENTRY_HEADER_SIZE) or ""
    if #entry_header ~= BND4_ENTRY_HEADER_SIZE
        or entry_header:sub(1, 8) ~= string.char(0x50, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF) then
        warnings[#warnings + 1] = {
            code = "invalid_menu_entry_header",
            path = path,
            message = "USER_DATA_010 的 BND4 项头无效",
        }
        return nil, nil
    end

    local entry_size = u32le(entry_header, 9)
    local entry_offset = u32le(entry_header, 17)
    if entry_size == nil or entry_size < 48 or entry_size > MAX_MENU_ENTRY_SIZE
        or entry_offset == nil or entry_offset < BND4_HEADER_SIZE
        or (file_size ~= nil and entry_offset + entry_size > file_size) then
        warnings[#warnings + 1] = {
            code = "invalid_menu_entry_range",
            path = path,
            message = "USER_DATA_010 的数据范围无效",
        }
        return nil, nil
    end

    local entry = repository:read(path, entry_offset, entry_size) or ""
    if #entry ~= entry_size then
        warnings[#warnings + 1] = {
            code = "truncated_menu_entry",
            path = path,
            message = "USER_DATA_010 数据不完整",
        }
        return nil, nil
    end

    local expected_checksum = entry:sub(1, 16)
    local actual_checksum = repository:md5(entry:sub(17))
    if actual_checksum == nil or actual_checksum ~= expected_checksum then
        warnings[#warnings + 1] = {
            code = "menu_checksum_mismatch",
            path = path,
            message = "USER_DATA_010 的 MD5 完整性校验失败",
        }
        return nil, nil
    end

    local iv = entry:sub(17, 32)
    local ciphertext = entry:sub(33)
    if #ciphertext % 16 ~= 0 then
        warnings[#warnings + 1] = {
            code = "invalid_menu_ciphertext",
            path = path,
            message = "USER_DATA_010 密文未按 AES 块对齐",
        }
        return nil, nil
    end

    local decrypted = repository:aes_128_cbc_decrypt(ciphertext, DS3_AES_KEY, iv)
    local menu = decrypted and strip_pkcs7(decrypted) or nil
    local minimum_size = MENU_PROFILE_OFFSET + MENU_PROFILE_STRIDE
        * (CHARACTER_SLOT_COUNT - 1) + PROFILE_NAME_BYTES
    if menu == nil or #menu < minimum_size then
        warnings[#warnings + 1] = {
            code = "menu_decryption_failed",
            path = path,
            message = "USER_DATA_010 解密或 PKCS#7 校验失败",
        }
        return nil, nil
    end

    local slots = {}
    for slot_index = 0, CHARACTER_SLOT_COUNT - 1 do
        local occupied = menu:byte(MENU_OCCUPANCY_OFFSET + slot_index + 1) ~= 0
        local name_offset = MENU_PROFILE_OFFSET + slot_index * MENU_PROFILE_STRIDE + 1
        local name = utf16le_name(menu, name_offset, PROFILE_NAME_BYTES)
        if name == nil then
            warnings[#warnings + 1] = {
                code = "invalid_character_name",
                path = path,
                slot = slot_index + 1,
                message = "角色名不是有效 UTF-16LE",
            }
        end
        slots[#slots + 1] = {
            index = slot_index + 1,
            occupied = occupied,
            character_name = name or "",
        }
        if occupied and (name == nil or name == "") then
            warnings[#warnings + 1] = {
                code = "occupied_slot_without_name",
                path = path,
                slot = slot_index + 1,
                message = "槽位标记为已占用，但角色名为空",
            }
        elseif not occupied and name and name ~= "" then
            warnings[#warnings + 1] = {
                code = "empty_slot_with_name",
                path = path,
                slot = slot_index + 1,
                message = "槽位标记为空，但角色摘要仍包含名称",
            }
        end
    end
    return slots, u64le(menu, 9)
end

function install(context)
    local problems = {}
    local repositories = {}
    local process_path = context.steam_executable(STEAM_APP_ID, EXECUTABLE_RELATIVE_PATH)
    if process_path == nil then
        problems[#problems + 1] = problem(
            "game_executable_not_found",
            "未在 Steam 库中找到 DARK SOULS III，可在 GUI 中手动选择 DarkSoulsIII.exe")
    end

    local roaming = context.known_folder("roaming_app_data")
    local save_root = roaming and context.path_join(roaming, "DarkSoulsIII") or nil
    local has_save = false
    if save_root and context.is_directory(save_root) then
        for _, account_path in ipairs(context.list_directories(save_root)) do
            local account = context.basename(account_path)
            if is_account_name(account)
                and context.is_file(context.path_join(account_path, "DS30000.sl2")) then
                has_save = true
                break
            end
        end
    end

    if has_save then
        repositories[1] = {
            path = save_root,
            include_globs = { "*/DS30000.sl2" },
            exclude_globs = { ".git/**", "GraphicsConfig.xml" },
        }
    else
        problems[#problems + 1] = problem(
            "save_not_found",
            "未找到有效的 DarkSoulsIII/<账号>/DS30000.sl2")
    end

    return {
        process_name = PROCESS_NAME,
        process_path = process_path,
        repositories = repositories,
        problems = problems,
    }
end

function parse(repository, changed_files)
    local accounts = {}
    local warnings = {}
    local changed = {}

    for _, path in ipairs(changed_files or {}) do
        changed[#changed + 1] = normalize_relative(path)
    end
    table.sort(changed)

    for _, original_path in ipairs(repository:files()) do
        local path = normalize_relative(original_path)
        local account = path:match("^([0-9a-fA-F]+)/[Dd][Ss]30000%.[Ss][Ll]2$")
        if account then
            local header = repository:read(original_path, 0, 64) or ""
            local stat = repository:stat(original_path) or {}
            local valid = header:sub(1, 4) == "BND4"
            local entry_count = valid and u32le(header, 13) or nil
            local slots, steam_id
            if valid then
                slots, steam_id = parse_slots(
                    repository, original_path, header, stat.size, warnings)
            end
            accounts[#accounts + 1] = {
                account_id = account,
                steam_id = steam_id and tostring(steam_id) or nil,
                path = path,
                valid = valid,
                container = valid and "BND4" or "unknown",
                container_entry_count = entry_count,
                slots = slots or {},
                file_size = stat.size,
                modified_unix_ns = stat.modified_unix_ns,
            }
            if not valid then
                warnings[#warnings + 1] = {
                    code = "invalid_sl2_header",
                    path = path,
                    message = "文件不是受支持的 BND4 DS3 存档，未尝试解析槽位",
                }
            end
        end
    end

    table.sort(accounts, function(left, right)
        return left.account_id:lower() < right.account_id:lower()
    end)

    return {
        game_id = "dark-souls-iii",
        repository = repository.path,
        accounts = accounts,
        changed_files = changed,
        warnings = warnings,
    }
end
