/* ... 前面的 include 和 定义保持不变 ... */

// [此处代码建议全量替换你的 handle_request 函数及其上方新增的辅助函数]

void send_file_response(int status, const char *content_type, const char *file, FILE *conn_fp) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        send_error(404, "Not Found", NULL, "File not found.", conn_fp);
        return;
    }
    fprintf(conn_fp, "HTTP/1.1 %d OK\r\n", status);
    fprintf(conn_fp, "Content-Type: %s\r\n", content_type);
    fprintf(conn_fp, "Connection: close\r\n\r\n");
    char buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        fwrite(buffer, 1, n, conn_fp);
    }
    fclose(fp);
}

void send_file_download(const char *file, FILE *conn_fp) {
    FILE *fp = fopen(file, "rb");
    if (!fp) {
        send_error(404, "Not Found", NULL, "File not found.", conn_fp);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fprintf(conn_fp, "HTTP/1.1 200 OK\r\n");
    fprintf(conn_fp, "Content-Type: application/octet-stream\r\n");
    fprintf(conn_fp, "Content-Disposition: attachment; filename=\"%s\"\r\n", file);
    fprintf(conn_fp, "Content-Length: %ld\r\n", file_size);
    fprintf(conn_fp, "Connection: close\r\n\r\n");
    char buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        fwrite(buffer, 1, n, conn_fp);
    }
    fclose(fp);
}

static void
handle_request(FILE *conn_fp, const conn_item_t *item)
{
	char line[4096];
	char *method, *path, *protocol, *authorization, *boundary;
	char *cur, *end, *cp, *file, *query;
	int len, login_state, method_id, do_logout, do_wxsend, clen = 0;
	struct mime_handler *handler;
	struct stat st, *p_st = NULL;
	uaddr conn_ip;
	time_t if_modified_since = (time_t)-1;

	authorization = boundary = NULL;

	if (!fgets(line, sizeof(line), conn_fp)) {
		send_error( 400, "Bad Request", NULL, "No request found.", conn_fp);
		return;
	}

	method = path = line;
	strsep(&path, " ");
	while (path && *path == ' ') path++;
	protocol = path;
	strsep(&protocol, " ");
	while (protocol && *protocol == ' ') protocol++;
	cp = protocol;
	strsep(&cp, " ");

	if ( !method || !path || !protocol ) {
		send_error( 400, "Bad Request", NULL, "Can't parse request.", conn_fp );
		return;
	}

	cur = protocol + strlen(protocol) + 1;
	end = line + sizeof(line) - 1;

	while ( (cur < end) && (fgets(cur, line + sizeof(line) - cur, conn_fp)) ) {
		if ( strcmp( cur, "\n" ) == 0 || strcmp( cur, "\r\n" ) == 0 ) break;
		if (strncasecmp(cur, "Accept-Language:", 16) == 0) {
			if (!http_has_lang) http_has_lang = set_preferred_lang(cur + 16);
		}
		else if (strncasecmp( cur, "Authorization:", 14) == 0) {
			cp = cur + 14; cp += strspn( cp, " \t" );
			authorization = cp; cur = cp + strlen(cp) + 1;
		}
		else if (strncasecmp( cur, "Content-Length:", 15) == 0) {
			cp = cur + 15; cp += strspn( cp, " \t" );
			clen = strtoul( cp, NULL, 0 );
		}
		else if (strncasecmp( cur, "If-Modified-Since:", 18) == 0) {
			cp = cur + 18; cp += strspn( cp, " \t" );
			if_modified_since = tdate_parse(cp);
		}
		else if ((cp = strstr( cur, "boundary=" ))) {
			boundary = cp + 9;
			for ( cp = cp + 9; *cp && *cp != '\r' && *cp != '\n'; cp++ );
			*cp = '\0'; cur = ++cp;
		}
	}

	if (strcasecmp(method, "get") == 0) method_id = HTTP_METHOD_GET;
	else if (strcasecmp(method, "head") == 0) method_id = HTTP_METHOD_HEAD;
	else if (strcasecmp(method, "post") == 0) method_id = HTTP_METHOD_POST;
	else {
		send_error( 501, "Not Implemented", NULL, "Unsupported method.", conn_fp );
		return;
	}

	if ( path[0] != '/' ) {
		send_error( 400, "Bad Request", NULL, "Bad URL.", conn_fp );
		return;
	}

	file = path + 1;
	len = strlen(file);
	if (len < 1) file = "index.asp";

	query = file;
	strsep(&query, "?");

	usockaddr_to_uaddr(&item->usa, &conn_ip);
	char ip_str[INET6_ADDRSTRLEN];
	convert_ip_to_string(&conn_ip, ip_str, sizeof(ip_str));

	login_state = http_login_check(&conn_ip);
	
	// 修正：如果没登录且访问敏感页面，跳转到登录页
	if (login_state == 0) {
		if (strstr(file, ".htm") != NULL || strstr(file, ".asp") != NULL) {
			file = "Nologin.asp";
			query = NULL;
		}
	}

	if (strcmp(file, "logout") == 0) {
		send_headers( 401, "Unauthorized", NULL, NULL, NULL, conn_fp );
		return;
	}

	for (handler = mime_handlers; handler->pattern; handler++) {
		if (match(handler->pattern, file)) break;
	}

	if (!handler->pattern) {
		send_error( 404, "Not Found", NULL, "URL was not found.", conn_fp );
		return;
	}

#if defined (SUPPORT_HTTPS)
	http_is_ssl = item->ssl;
#endif

	do_logout = (strcmp(file, "Logout.asp") == 0) ? 1 : 0;
    // 识别后台自动刷新页面，不触发推送
	do_wxsend = ((strcmp(file, "log_content.asp") == 0) || (strcmp(file, "system_status_data.asp") == 0) || (strcmp(file, "status_internet.asp") == 0)) ? 1 : 0;

    // --- 权限检查逻辑 ---
	if (handler->need_auth && login_state > 1 && !do_logout) {
		if (!auth_check(authorization, ip_str, do_wxsend)) {
			http_logout(&conn_ip);
			if (method_id == HTTP_METHOD_POST) eat_post_data(conn_fp, clen);
			send_authenticate(conn_fp);
			return;
		}
		
		if (login_state == 2) {
			http_login(&conn_ip);
			if (!do_wxsend) {
                // 成功登录推送
                logmessage("httpd", "用户IP:【%s】 成功登录管理界面！", ip_str);
                if (nvram_get_int("wxsend_enable") && (nvram_get_int("wxsend_login") == 1 || nvram_get_int("wxsend_login") == 3)) {
                    char wx_command[1024];
                    const char *wx_title = nvram_get("wxsend_title") ? : "WEB登录";
                    snprintf(wx_command, sizeof(wx_command), "/usr/bin/wxsend.sh send_message \"【%s】\" \"用户IP：\" \"%s\" \"成功登录管理界面！\"", wx_title, ip_str);
                    system(wx_command);
                }
            }
		}
	}

    /* 安全修正：etc/ 或 tmp/ 路径访问必须放在登录校验之后！ */
	if (strncmp(file, "etc/", 4) == 0 || strncmp(file, "tmp/", 4) == 0) {
    		char *ext = strrchr(file, '.');
    		if (ext) {
        		if (strcasecmp(ext, ".html") == 0 || strcasecmp(ext, ".asp") == 0) {
            			send_file_response(200, "text/html", file, conn_fp);
            			return;
        		} else if (strcasecmp(ext, ".txt") == 0) {
            			send_file_response(200, "text/plain; charset=utf-8", file, conn_fp);
            			return;
        		}
    		}
    		send_file_download(file, conn_fp);
    		return;
	}

	if (method_id == HTTP_METHOD_POST) {
		if (handler->input) handler->input(file, conn_fp, clen, boundary);
		else eat_post_data(conn_fp, clen);
		try_pull_data(conn_fp, item->fd);
	} else {
		if (query) do_uncgi_query(query);
		else if (handler->output == do_ej) do_cgi_clear();
	}

	if (handler->output == do_file) {
		if (stat(file, &st) == 0 && !S_ISDIR(st.st_mode)) {
			p_st = &st;
			if (!handler->extra_header && if_modified_since != (time_t)-1 && if_modified_since == st.st_mtime) {
				st.st_size = 0;
				send_headers( 304, "Not Modified", NULL, handler->mime_type, p_st, conn_fp );
				return;
			}
		}
	}

	send_headers( 200, "OK", handler->extra_header, handler->mime_type, p_st, conn_fp );
	if (method_id != HTTP_METHOD_HEAD && handler->output) {
		handler->output(file, conn_fp);
	}
	if (do_logout) http_logout(&conn_ip);
}
