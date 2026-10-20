"""Small, count-checked listener hooks over the SHA-verified portable source."""
def prepare_listener(source):
    def hook(old, new, count=1):
        nonlocal source
        if source.count(old) != count:
            raise ValueError('listener hook changed: ' + old[:100])
        source = source.replace(old, new)
    hook('#include "mongoose/mongoose.h"', '#include "mongoose/mongoose.h"\n#include "listener_arrival_probe.h"\n#include "listener_pair.h"')
    hook('int main(int argc, char *argv[]) {', '''#include "listen_address.h"
#include "managed_listener_address_win32.h"
#include "listener_pair.h"
#include "listener_startup_win32.h"
int main(int argc, char *argv[]) {
    int startup_action = ms_cli(argc, argv);
    if (startup_action >= 0) return startup_action;
    int address_action = ma_cli(argc, argv);
    if (address_action >= 0) return address_action;
    int listener_check = lp_check_cli(argc, argv, 80, 443, 8686);
    if (listener_check >= 0) return listener_check;''')
    # The parser uses the shared normalizer too, so include before settings.
    hook('    bool              bind_all;   /* listen on all interfaces */',
         '    lp_pair listeners;\n    bool auto_create;\n    char bind_ip[64];\n    bool              bind_all;   /* listen on all interfaces */')
    hook('static struct settings parse_cli_parameters(', '#include "listener_pair.h"\nstatic struct settings parse_cli_parameters(')
    hook('''    /* The management port only answers the internal endpoints. */''', '''    if (ap_reply(c, hm)) return;
    /* A LAN response binding must never become a public forward proxy. */
    if (s->proxy_filter && !internal_endpoint_reachable(c, s)) {
        mg_http_reply(c, 403, "Content-Type: text/plain\\r\\n", "forbidden");
        return;
    }
    /* The management port only answers the internal endpoints. */''')
    hook('''        } else if (strcmp(argv[i], "--bind") == 0 && i < argc-1) {''', '''        } else if ((strcmp(argv[i], "--listen-ipv4") == 0 || strcmp(argv[i], "--listen-ipv6") == 0) && i < argc-1) {
            const char *key=argv[i];
            if (!lp_set(&s.listeners,key,argv[++i])) {
                s_cli_error="Invalid listener family or literal"; s.init=false; return s;
            }
            s.cli_bind_set=true;
        } else if (strcmp(argv[i], "--bind-ip") == 0 && i < argc-1) {
            if (!la_normalize(argv[++i], s.bind_ip)) {
                s_cli_error = "--bind-ip requires an IPv4 or IPv6 literal";
                s.init = false; return s;
            }
            s.cli_bind_set = true;
        } else if (strcmp(argv[i], "--bind") == 0 && i < argc-1) {''')
    hook('''                    else if (sscanf(line, "stats_port=%d", &v) == 1 && !s.cli_stats_port_set)''', '''                    else if ((!strncmp(line,"listen_ipv4=",12) || !strncmp(line,"listen_ipv6=",12)) && !s.cli_bind_set) {
                        char *value=line+12; value[strcspn(value,"\\r\\n")]=0;
                        if (!lp_set(&s.listeners,line[10]=='4' ? "--listen-ipv4" : "--listen-ipv6",*value ? value : "-")) {
                            fclose(f); LOG_FATAL("Invalid listener pair in webserver.ini"); return EXIT_FAILURE;
                        }
                    }
                    else if (!strncmp(line,"listener_auto_create=",21)) {
                        line[strcspn(line,"\\r\\n")]=0;
                        if (strcmp(line+21,"0") && strcmp(line+21,"1")) {
                            fclose(f); LOG_FATAL("Invalid listener_auto_create"); return EXIT_FAILURE;
                        }
                        s.auto_create=line[21]=='1';
                    }
                    else if (strncmp(line, "bind_ip=", 8) == 0 && !s.cli_bind_set) {
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
    if (s.listeners.explicit_pair && !*s.listeners.ipv4 && !*s.listeners.ipv6) {
        LOG_FATAL("At least one listener family must be enabled"); return EXIT_FAILURE;
    }
    DWORD address_start_error=s.auto_create ? ms_startup(&s.listeners,s.bind_ip,s.bind_all,s.http_port,s.https_port) : NO_ERROR;
    if (address_start_error) LOG_WARN("Managed listener preparation failed (%lu); response listeners remain stopped",(unsigned long)address_start_error);
    /* Autostart entry self-heal:''')
    hook('''        args.bind_all = s.bind_all;''', '''        args.bind_all = s.bind_all;
        args.bind_ip = s.listeners.explicit_pair ? s.listeners.ipv4 : s.bind_ip;
        args.bind_ipv6 = s.listeners.ipv6;
        args.explicit_pair = s.listeners.explicit_pair != 0;
        args.auto_create = s.auto_create;''', 2)
    hook('''        snprintf(cmd, sizeof(cmd), "\\"%s\\" --resources \\"%s\\" --http-port %d --https-port %d "
                 "--stats-port %d --minimized",
                 exe, s.resource_dir, s.http_port, s.https_port, s.stats_port);''',
         '''        snprintf(cmd, sizeof(cmd), "\\"%s\\" --resources \\"%s\\" --minimized", exe, s.resource_dir);''')
    begin = source.index('    const char *v4 = s.bind_all ? "0.0.0.0" : "127.0.0.1";')
    end = source.index('\n\n    char startup_warning', begin)
    source = source[:begin] + '''    lp_urls(&s.listeners, s.bind_ip, s.bind_all, s.http_port, s.https_port,
            http_url, https_url, http_url6, https_url6);''' + source[end:]
    begin=source.index('    char startup_warning[512] = {0};')
    end=source.index('    /* Extra ad-block monitoring:',begin)
    source=source[:begin]+'    char startup_warning[512] = {0};\n    struct mg_connection *response[4]={0};\n    const char *urls[4]={http_url,https_url,http_url6,https_url6};\n    const char *names[4]={"http","https","http6","https6"};\n    bool failed=address_start_error!=NO_ERROR;\n    if (!failed) for (int i=0;i<4;i++) if (*urls[i]) {\n        response[i]=bind_try(&mgr,urls[i],fn,&s,names[i]);\n        if (!response[i] && (s.listeners.explicit_pair || i==0)) failed=true;\n        if (!response[i]) LOG_WARN("Configured listener failed: %s",urls[i]);\n    }\n    if (failed) {\n        for (int i=0;i<4;i++) if (response[i]) response[i]->is_closing=1;\n        mg_mgr_poll(&mgr,0);\n        snprintf(startup_warning,sizeof(startup_warning),address_start_error\n            ? "Address auto-creation failed (%lu). Response listeners stopped. Retry in Settings."\n            : "Required listener failed (%lu). All response listeners stopped; check both families and ports in Settings.",\n            (unsigned long)address_start_error);\n        LOG_WARN("%s",startup_warning);\n        if (s.no_gui) { mg_mgr_free(&mgr); return EXIT_FAILURE; }\n    }\n    s_main_http_bound=!failed && response[0]!=NULL;\n    bool ipv6_ok=!failed && ((strchr(http_url,\'[\') && response[0] && response[1])\n            || (*http_url6 && response[2] && response[3]));\n\n' +source[end:]
    hook('''        if (s.http_port != 80) {''', '''        if (!address_start_error && !s.listeners.explicit_pair && !*s.bind_ip && s.http_port != 80) {''')
    hook('''        if (s.https_port != 443) {''', '''        if (!address_start_error && !s.listeners.explicit_pair && !*s.bind_ip && s.https_port != 443) {''')
    return source
