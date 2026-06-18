// Vulnerable: VUL-CVE-2016-5354
u3v_conv_info = wmem_new0(wmem_file_scope(), u3v_conv_info_t);
        usb_conv_info->class_data = u3v_conv_info;
    }
// --- packet-usb-audio.c ---
        audio_conv_info = wmem_new(wmem_file_scope(), audio_conv_info_t);
        usb_conv_info->class_data = audio_conv_info;
        /* XXX - set reasonable default values for all components
           that are not filled in by this function */
...
        /* XXX - set reasonable default values for all components
           that are not filled in by this function */
...
            video_conv_info->entities = wmem_tree_new(wmem_file_scope());
            usb_conv_info->class_data = video_conv_info;
        }
