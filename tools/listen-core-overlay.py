"""Small, count-checked listener hooks over the SHA-verified portable source."""
def prepare_listener(source):
    def hook(old, new, count=1):
        nonlocal source
        if source.count(old) != count:
            raise ValueError('listener hook changed: ' + old[:100])
        source = source.replace(old, new)
    hook('int main(int argc, char *argv[]) {', '''#include "listen_address.h"
int main(int argc, char *argv[]) {
    int listener_check = la_check_cli(argc, argv, 80, 443, 8686);
    if (listener_check >= 0) return listener_check;''')
    # The parser uses the shared normalizer too, so include before settings.
    hook('    bool              bind_all;   /* listen on all interfaces */',
         '    char bind_ip[64];\n    bool              bind_all;   /* listen on all interfaces */')
    hook('static struct settings parse_cli_parameters(', '#include "listen_address.h"\nstatic struct settings parse_cli_parameters(')
    hook('''        } else if (strcmp(argv[i], "--bind") == 0 && i < argc-1) {''', '''        } else if (strcmp(argv[i], "--bind-ip") == 0 && i < argc-1) {
            if (!la_normalize(argv[++i], s.bind_ip)) {
                s_cli_error = "--bind-ip requires an IPv4 or IPv6 literal";
                s.init = false; return s;
            }
            s.cli_bind_set = true;
        } else if (strcmp(argv[i], "--bind") == 0 && i < argc-1) {''')
    hook('''                    else if (sscanf(line, "stats_port=%d", &v) == 1 && !s.cli_stats_port_set)''', '''                    else if (strncmp(line, "bind_ip=", 8) == 0 && !s.cli_bind_set) {
                        char *value = line + 8; value[strcspn(value, "\\r\\n")] = 0;
                        if (*value && !la_normalize(value, s.bind_ip)) {
                            fclose(f); LOG_FATAL("Invalid bind_ip in webserver.ini"); return EXIT_FAILURE;
                        }
                    }
                    else if (sscanf(line, "stats_port=%d", &v) == 1 && !s.cli_stats_port_set)''')
    hook('''    /* Autostart entry self-heal:''', '''    if (s.http_port < 1 || s.http_port > 65535 || s.https_port < 1 || s.https_port > 65535
            || s.stats_port < 1 || s.stats_port > 65535 || s.http_port == s.https_port
            || s.http_port == s.stats_port || s.https_port == s.stats_port) {
        LOG_FATAL("Invalid or overlapping listener ports in configuration"); return EXIT_FAILURE;
    }
    /* Autostart entry self-heal:''')
    hook('''        args.bind_all = s.bind_all;''', '''        args.bind_all = s.bind_all;
        args.bind_ip = s.bind_ip;''', 2)
    hook('''        snprintf(cmd, sizeof(cmd), "\\"%s\\" --resources \\"%s\\" --http-port %d --https-port %d "
                 "--stats-port %d --minimized",
                 exe, s.resource_dir, s.http_port, s.https_port, s.stats_port);''',
         '''        snprintf(cmd, sizeof(cmd), "\\"%s\\" --resources \\"%s\\" --minimized", exe, s.resource_dir);''')
    begin = source.index('    const char *v4 = s.bind_all ? "0.0.0.0" : "127.0.0.1";')
    end = source.index('\n\n    char startup_warning', begin)
    source = source[:begin] + '''    la_urls(s.bind_ip, s.bind_all, s.http_port, s.https_port,
            http_url, https_url, http_url6, https_url6);''' + source[end:]
    hook('if (bind_try(&mgr, http_url6,', 'if (*http_url6 && bind_try(&mgr, http_url6,')
    hook('if (bind_try(&mgr, https_url6,', 'if (*https_url6 && bind_try(&mgr, https_url6,')
    hook('''        if (s.http_port != 80) {''', '''        if (!*s.bind_ip && s.http_port != 80) {''')
    hook('''        if (s.https_port != 443) {''', '''        if (!*s.bind_ip && s.https_port != 443) {''')
    return source
