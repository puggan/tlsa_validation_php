<?php

	require_once("db.conf.php");

	function dns_fetch_tls($domain, $port = 443)
	{
		global $database;

		$port = (int) $port;

		$tls_domain = "_{$port}._tcp.{$domain}";

		$command = "dig +short TLSA " . escapeshellarg($tls_domain);

		$tlsa_row = exec($command);

		if(!$tlsa_row) return FALSE;

		$tlsa_parts = explode(" ", $tlsa_row);

		$data = array();
		$data['usage'] = (int) array_shift($tlsa_parts);
		$data['selector'] = (int) array_shift($tlsa_parts);
		$data['matchingtype'] = (int) array_shift($tlsa_parts);
		$data['hash'] = implode("", $tlsa_parts);

		$where_parts = array();
		$where_parts[] = "domain = " . $database->quote($domain);
		$where_parts[] = "usage = " . $data['usage'];
		$where_parts[] = "selector = " . $data['selector'];
		$where_parts[] = "matchingtype = " . $data['matchingtype'];
		$where_parts[] = "hash = " . $database->quote($data['hash']);

		$update = $database->update("UPDATE tlsa SET pulse = NOW() WHERE " . implode(" AND ", $where_parts));

		if(!$update)
		{
			$set_parts = $where_parts;
			$set_parts[] = "birth = NOW()";
			$set_parts[] = "pulse = NOW()";

			$database->write("REPLACE INTO tlsa SET " . implode(", ", $set_parts));
		}

		return $data;
	}

	function ssl_load_cert($domain, $port = 443)
	{
		global $database;

		$port = (int) $port;
		$domain_sql = $database->quote($domain);

		$data =  $database->get("SELECT * FROM connections INNER JOIN cert USING (sha256) WHERE domain = {$domain_sql} AND port = {$port}");

		if(!$data) return FALSE;

		$data['cert'] = openssl_x509_read($data['content']);

		return $data;
	}

	function ssl_load_cert_sha256($sha256)
	{
		global $database;

		$sha256_sql = $database->quote($sha256);

		$data =  $database->get("SELECT * FROM cert WHERE sha256 = {$sha256_sql}");

		if(!$data) return FALSE;

		$data['cert'] = openssl_x509_read($data['content']);

		return $data;
	}

	function ssl_fetch_cert($domain, $port = 443, $protocol = NULL)
	{
		global $database;

		$port = (int) $port;
		$domain_sql = $database->quote($domain);

		if(!dns_get_record($domain, DNS_A)) return FALSE;

		$connection_context_option = array();
		$connection_context_option['ssl']['capture_peer_cert'] = TRUE;
		$connection_context_option['ssl']['capture_peer_cert_chain'] = TRUE;
		$connection_context = stream_context_create($connection_context_option);

		$errno = 0;
		$errstr = '';
		$url = "tcp://{$domain}:{$port}";
		$connection_client = stream_socket_client($url, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $connection_context);

		if(!$connection_client) return FALSE;

		if($protocol == 'auto')
		{
			switch($port)
			{
				case 25:
				case 587:
				{
					$protocol = 'smtp';
					break;
				}
			}
		}

		switch($protocol)
		{
			case 'smtp':
			{
				stream_set_timeout($connection_client, 2);
				fread($connection_client, 10240);
				fwrite($connection_client, "STARTTLS\n");
				fread($connection_client, 10240);
				break;
			}
		}

		stream_socket_enable_crypto($connection_client, TRUE, STREAM_CRYPTO_METHOD_SSLv23_CLIENT);
		$connection_info = stream_context_get_params($connection_client);
		$certificate = $connection_info['options']['ssl']['peer_certificate'];
		$certificate_chain = $connection_info['options']['ssl']['peer_certificate_chain'];
		fclose($connection_client);

		if(!$certificate) return FALSE;

		$chain_list = array();
		$last_chain_sha256 = '';
		$last_chain_sha256_sql = '';
		while($chain_cert = array_pop($certificate_chain))
// 		foreach($connection_info['options']['ssl']['peer_certificate_chain'] as $depth => $chain_cert)
		{
			$chain_sha256 = openssl_x509_fingerprint($chain_cert, 'sha256');

			if($chain_sha256 == $last_chain_sha256)
			{
				continue;
			}


			$chain_sha256_sql = $database->quote($chain_sha256);
			$chain_list[] = $chain_sha256;
// 			$updated = $database->update("UPDATE cert SET pulse = NOW() WHERE sha256 = {$chain_sha256_sql}");
			$updated = $database->update("UPDATE cert SET parent = {$last_chain_sha256_sql}, pulse = NOW() WHERE sha256 = {$chain_sha256_sql}");

			if(!$updated)
			{
				$cert_output = '';
				openssl_x509_export($chain_cert, $cert_output);
				$cert_content_sql = $database->quote($cert_output);
				$database->write("INSERT INTO cert SET sha256 = {$chain_sha256_sql}, parent = {$last_chain_sha256_sql}, birth = NOW(), pulse = NOW(), content = {$cert_content_sql}");
			}

			$last_chain_sha256 = $chain_sha256;
			$last_chain_sha256_sql = $chain_sha256_sql;
		}

		$sha256 = openssl_x509_fingerprint($certificate, 'sha256');
		$sha256_sql = $database->quote($sha256);

		$updated = $database->update("UPDATE cert SET pulse = NOW() WHERE sha256 = {$sha256_sql}");

		if(!$updated)
		{
			$cert_output = '';
			openssl_x509_export($certificate, $cert_output);
			$cert_content_sql = $database->quote($cert_output);
			$database->write("INSERT INTO cert SET sha256 = {$sha256_sql}, birth = NOW(), pulse = NOW(), content = {$cert_content_sql}");
		}

		$updated = $database->update("UPDATE connections SET pulse = NOW() WHERE domain = {$domain_sql} AND port = {$port} AND sha256 = {$sha256_sql}");

		if(!$updated)
		{
			$database->write("REPLACE INTO connections SET domain = {$domain_sql}, port = {$port}, sha256 = {$sha256_sql}, birth = NOW(), pulse = NOW()");
		}

		return array('domain' => $domain, 'port' => $port, 'sha256' => $sha256, 'cert' => $certificate, 'chain' => $chain_list, 'pulse' => TRUE);
	}

	function html_options($list, $selected)
	{
		$selected = (string) $selected;

		$html = array();

		foreach($list as $key => $title)
		{
			$key = (string) $key;

			$selected_html = ($key == $selected) ? ' selected="selected"' : '';
			$key = htmlentities($key);
			$title = htmlentities($title);

			$html[] = "<option value=\"{$key}\"{$selected_html}>{$title}</option>";
		}

		return implode(PHP_EOL, $html);
	}
