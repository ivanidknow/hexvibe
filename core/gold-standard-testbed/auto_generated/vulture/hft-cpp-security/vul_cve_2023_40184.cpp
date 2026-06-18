// Vulnerable: VUL-CVE-2023-40184
enum scp_screate_status status = E_SCP_SCREATE_GENERAL_ERROR;

    auth_start_session(login_info->auth_info, s->display);
#ifdef USE_BSD_SETLOGIN
    /**
// --- verify_user_pam.c ---
/* returns error */
int
auth_start_session(struct auth_info *auth_info, int display_num)
{
    int error;
...
    auth_info->session_opened = 1;
    return 0;
}
