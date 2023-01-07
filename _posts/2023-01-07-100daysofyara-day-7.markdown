---
layout: post
title: "100 Days of YARA - Day 7"
date: 2023-01-07 00:00:00 -0000
categories: yara
---

# Parsing an LNK file with the LNK module
The nice thing about the YARA file parsing modules is that you can output the populated variables by adding the `-D` flag on the command line. If you would like to test this out, and don't have LNKs to hand, then sample LNK files can be found in the `tests\data` directory of the LNK module branch (all prefixed with `lnk-`). So if you save the following rule to `test_lnk.yar`:
```
import "lnk"

rule test {
    condition:
        filesize > 0
}
```
And run the command `yara -D test_lnk.yar tests/data/lnk-standard` (where `lnk-standard` is provided in the [LNK documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)), you should see the following output:
```
lnk
        is_malformed = 0
        overlay_offset = YR_UNDEFINED
        has_overlay = 0
        vista_and_above_id_list_data
                item_id_list
                number_of_item_ids = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_vista_and_above_id_list_data = 0
        tracker_data
                droid_birth_file_identifier = "\xecF\xcd{"\x7f\xdd\x11\x94\x99\x00\x13r\x16\x87J"
                droid_birth_volume_identifier = "@x\xc7\x94G\xfa\xc7F\xb3V\-\xc6\xb6\xd1\x15"
                droid_file_identifier = "\xecF\xcd{"\x7f\xdd\x11\x94\x99\x00\x13r\x16\x87J"
                droid_volume_identifier = "@x\xc7\x94G\xfa\xc7F\xb3V\-\xc6\xb6\xd1\x15"
                machine_id = "chris-xps"
                block_signature = 2684354563
                block_size = 96
        has_tracker_data = 1
        special_folder_data
                offset = YR_UNDEFINED
                special_folder_id = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_special_folder_data = 0
        shim_data
                layer_name = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_shim_data = 0
        property_store_data
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_property_store_data = 0
        known_folder_data
                known_folder_id
                offset = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_known_folder_data = 0
        icon_environment_data
                target_unicode = YR_UNDEFINED
                target_ansi = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_icon_environment_data = 0
        environment_variable_data
                target_unicode = YR_UNDEFINED
                target_ansi = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_environment_variable_data = 0
        darwin_data
                darwin_data_unicode = YR_UNDEFINED
                darwin_data_ansi = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_darwin_data = 0
        console_fe_data
                code_page = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_console_fe_data = 0
        console_data
                color_table
                history_no_dup = YR_UNDEFINED
                number_of_history_buffers = YR_UNDEFINED
                history_buffer_size = YR_UNDEFINED
                auto_position = YR_UNDEFINED
                insert_mode = YR_UNDEFINED
                quick_edit = YR_UNDEFINED
                full_screen = YR_UNDEFINED
                cursor_size = YR_UNDEFINED
                face_name = YR_UNDEFINED
                font_weight = YR_UNDEFINED
                font_family = YR_UNDEFINED
                font_size = YR_UNDEFINED
                window_origin_y = YR_UNDEFINED
                window_origin_x = YR_UNDEFINED
                window_size_y = YR_UNDEFINED
                window_size_x = YR_UNDEFINED
                screen_buffer_size_y = YR_UNDEFINED
                screen_buffer_size_x = YR_UNDEFINED
                popup_fill_attributes = YR_UNDEFINED
                fill_attributes = YR_UNDEFINED
                block_signature = YR_UNDEFINED
                block_size = YR_UNDEFINED
        has_console_data = 0
        icon_location = YR_UNDEFINED
        command_line_arguments = YR_UNDEFINED
        working_dir = "C\x00:\x00\\x00t\x00e\x00s\x00t\x00"
        relative_path = ".\x00\\x00a\x00.\x00t\x00x\x00t\x00"
        name_string = YR_UNDEFINED
        link_info
                common_path_suffix_unicode = YR_UNDEFINED
                local_base_path_unicode = YR_UNDEFINED
                common_path_suffix = "\x00"
                common_network_relative_link
                        device_name_unicode = YR_UNDEFINED
                        net_name_unicode = YR_UNDEFINED
                        device_name = YR_UNDEFINED
                        net_name = YR_UNDEFINED
                        device_name_offset_unicode = YR_UNDEFINED
                        net_name_offset_unicode = YR_UNDEFINED
                        network_provider_type = YR_UNDEFINED
                        device_name_offset = YR_UNDEFINED
                        net_name_offset = YR_UNDEFINED
                        flags = YR_UNDEFINED
                        size = YR_UNDEFINED
                has_common_network_relative_link = YR_UNDEFINED
                local_base_path = "C:\test\a.txt"
                volume_id
                        data = "\x00"
                        volume_label_offset_unicode = YR_UNDEFINED
                        volume_label_offset = 16
                        drive_serial_number = 813337217
                        drive_type = 3
                        size = 17
                has_volume_id = 1
                common_path_suffix_offset_unicode = YR_UNDEFINED
                local_base_path_offset_unicode = YR_UNDEFINED
                common_path_suffix_offset = 59
                common_network_relative_link_offset = 0
                local_base_path_offset = 45
                volume_id_offset = 28
                flags = 1
                header_size = 28
                size = 60
        link_target_id_list
                item_id_list_size = 189
                number_of_item_ids = 4
                item_id_list
                        [0]
                                size = 18
                                data = "\x1fP\xe0O\xd0 \xea:i\x10\xa2\xd8\x08\x00+00\x9d"
                        [1]
                                size = 23
                                data = "/C:\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        [2]
                                size = 68
                                data = "1\x00\x00\x00\x00\x00,9i\xa3\x10\x00test\x00\x002\x00\x07\x00\x04\x00\xef\xbe,9e\xa3,9i\xa3&\x00\x00\x00\x03\x1e\x00\x00\x00\x00\xf5\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00\x14\x00"
                        [3]
                                size = 70
                                data = "2\x00\x00\x00\x00\x00,9i\xa3 \x00a.txt\x004\x00\x07\x00\x04\x00\xef\xbe,9i\xa3,9i\xa3&\x00\x00\x00-n\x00\x00\x00\x00\x96\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00a\x00.\x00t\x00x\x00t\x00\x00\x00\x14\x00"
        has_hotkey = 0
        hotkey_modifier_flags = 0
        hotkey = YR_UNDEFINED
        hotkey_flags = 0
        show_command = 1
        icon_index = 0
        file_attributes_flags = 32
        link_flags = 524443
        file_size = 0
        write_time = 1221251237
        access_time = 1221251237
        creation_time = 1221251237
        is_lnk = 1
        TMPF_DEVICE = 8
        TMPF_TRUETYPE = 4
        TMPF_VECTOR = 2
        TMPF_FIXED_PITCH = 1
        TMPF_NONE = 0
        FF_DECORATIVE = 80
        FF_SCRIPT = 64
        FF_MODERN = 48
        FF_SWISS = 32
        FF_ROMAN = 16
        FF_DONTCARE = 0
        BACKGROUND_INTENSITY = 128
        BACKGROUND_RED = 64
        BACKGROUND_GREEN = 32
        BACKGROUND_BLUE = 16
        FOREGROUND_INTENSITY = 8
        FOREGROUND_RED = 4
        FOREGROUND_GREEN = 2
        FOREGROUND_BLUE = 1
        WNNC_NET_GOOGLE = 4390912
        WNNC_NET_MS_NFS = 4325376
        WNNC_NET_MFILES = 4259840
        WNNC_NET_RSFX = 4194304
        WNNC_NET_VMWARE = 4128768
        WNNC_NET_DRIVEONWEB = 4063232
        WNNC_NET_ZENWORKS = 3997696
        WNNC_NET_KWNP = 3932160
        WNNC_NET_DFS = 3866624
        WNNC_NET_AVID1 = 3801088
        WNNC_NET_OPENAFS = 3735552
        WNNC_NET_QUINCY = 3670016
        WNNC_NET_SRT = 3604480
        WNNC_NET_TERMSRV = 3538944
        WNNC_NET_LOCK = 3473408
        WNNC_NET_IBMAL = 3407872
        WNNC_NET_SHIVA = 3342336
        WNNC_NET_HOB_NFS = 3276800
        WNNC_NET_MASFAX = 3211264
        WNNC_NET_OBJECT_DIRE = 3145728
        WNNC_NET_KNOWARE = 3080192
        WNNC_NET_DAV = 3014656
        WNNC_NET_EXIFS = 2949120
        WNNC_NET_YAHOO = 2883584
        WNNC_NET_FOXBAT = 2818048
        WNNC_NET_STAC = 2752512
        WNNC_NET_EXTENDNET = 2686976
        WNNC_NET_3IN1 = 2555904
        WNNC_NET_CSC = 2490368
        WNNC_NET_RDR2SAMPLE = 2424832
        WNNC_NET_TWINS = 2359296
        WNNC_NET_DISTINCT = 2293760
        WNNC_NET_FJ_REDIR = 2228224
        WNNC_NET_PROTSTOR = 2162688
        WNNC_NET_DECORB = 2097152
        WNNC_NET_RIVERFRONT2 = 2031616
        WNNC_NET_RIVERFRONT1 = 1966080
        WNNC_NET_SERNET = 1900544
        WNNC_NET_MANGOSOFT = 1835008
        WNNC_NET_DOCUSPACE = 1769472
        WNNC_NET_AVID = 1703936
        VALID_NET_TYPE = 2
        VALID_DEVICE = 1
        DRIVE_RAMDISK = 6
        DRIVE_CDROM = 5
        DRIVE_REMOTE = 4
        DRIVE_FIXED = 3
        DRIVE_REMOVABLE = 2
        DRIVE_NO_ROOT_DIR = 1
        DRIVE_UNKNOWN = 0
        COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX = 2
        VOLUME_ID_AND_LOCAL_BASE_PATH = 1
        HOTKEYF_ALT = 4
        HOTKEYF_CONTROL = 2
        HOTKEYF_SHIFT = 1
        SW_SHOWMINNOACTIVE = 7
        SW_SHOWMAXIMIZED = 3
        SW_SHOWNORMAL = 1
        FILE_ATTRIBUTE_ENCRYPTED = 16384
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 8192
        FILE_ATTRIBUTE_OFFLINE = 4096
        FILE_ATTRIBUTE_COMPRESSED = 2048
        FILE_ATTRIBUTE_REPARSE_POINT = 1024
        FILE_ATTRIBUTE_SPARSE_FILE = 512
        FILE_ATTRIBUTE_TEMPORARY = 256
        FILE_ATTRIBUTE_NORMAL = 128
        RESERVED_2 = 64
        FILE_ATTRIBUTE_ARCHIVE = 32
        FILE_ATTRIBUTE_DIRECTORY = 16
        RESERVED_1 = 8
        FILE_ATTRIBUTE_SYSTEM = 4
        FILE_ATTRIBUTE_HIDDEN = 2
        FILE_ATTRIBUTE_READONLY = 1
        KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET = 67108864
        PREFER_ENVIRONMENT_PATH = 33554432
        UNALIAS_ON_SAVE = 16777216
        ALLOW_LINK_TO_LINK = 8388608
        DISABLE_KNOWN_FOLDER_ALIAS = 4194304
        DISABLE_KNOWN_FOLDER_TRACKING = 2097152
        DISABLE_LINK_PATH_TRACKING = 1048576
        ENABLE_TARGET_METADATA = 524288
        FORCE_NO_LINK_TRACK = 262144
        RUN_WITH_SHIM_LAYER = 131072
        UNUSED_2 = 65536
        NO_PIDL_ALIAS = 32768
        HAS_EXP_ICON = 16384
        RUN_AS_USER = 8192
        HAS_DARWIN_ID = 4096
        UNUSED_1 = 2048
        RUN_IN_SEPARATE_PROCESS = 1024
        HAS_EXP_STRING = 512
        FORCE_NO_LINK_INFO = 256
        IS_UNICODE = 128
        HAS_ICON_LOCATION = 64
        HAS_ARGUMENTS = 32
        HAS_WORKING_DIR = 16
        HAS_RELATIVE_PATH = 8
        HAS_NAME = 4
        HAS_LINK_INFO = 2
        HAS_LINK_TARGET_ID_LIST = 1
test tests/data/lnk-standard
```
The variables printed are the ones that are set by the LNK module, in reverse order of when they have been parsed. They are a combination of fixed values (i.e. the symbolic constants defined in the LNK docs), parsed values from the LNK (either as single variables, or arrays/dictionaries), and some boolean values set about general information of the LNK.

The layer of indentation corresponds to how you can access the variable. If you want to access the `file_size` variable, you would do so via `lnk.file_size`. If you want to access `number_of_item_ids`, you can via `lnk.link_target_id_list.number_of_item_ids`.

As you can see, not all variables are set. The LNK file specification points out that many sections of the file format are optional, so don't expect the majority of variables to be set on each LNK file you parse!

If you want detail on each of the variables parsed out/available, they are documented in `docs\modules\lnk.rst` (which you'll have to build yourself or just read the `.rst` file in a text editor). I've also manually converted these docs to markdown for these blog posts (although they won't remain up to date with any changes) which you can find here: [https://bitsofbinary.github.io/yara/2023/01/05/lnk_module_documentation.html](https://bitsofbinary.github.io/yara/2023/01/05/lnk_module_documentation.html)