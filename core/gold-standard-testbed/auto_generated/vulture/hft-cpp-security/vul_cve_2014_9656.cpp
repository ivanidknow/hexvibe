// Vulnerable: VUL-CVE-2014-9656
2014-02-08  Dave Arnold  <darnold@adobe.com>
// --- ttsbit.c ---
#ifdef FT_CONFIG_OPTION_USE_PNG
        loader = tt_sbit_decoder_load_png;
#else
        error = FT_THROW( Unimplemented_Feature );
...
#else
        error = FT_THROW( Unimplemented_Feature );
#endif /* FT_CONFIG_OPTION_USE_PNG */
        break;
...
        break;

      default:
