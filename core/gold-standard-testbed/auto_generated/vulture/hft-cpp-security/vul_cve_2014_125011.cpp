// Vulnerable: VUL-CVE-2014-125011
case '0': case '1': case '2': case '3': case '4':
case '5': case '6': case '7': case '8': case '9':
    if (s->nb_args < MAX_NB_ARGS)
        s->args[s->nb_args] = FFMAX(s->args[s->nb_args], 0) * 10 + buf[0] - '0';
    break;
