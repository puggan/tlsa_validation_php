<?php

	require_once("functions.php");

	$default = array();
	$default['domain'] = 'tlsa.puggan.se';
	$default['port'] = 443;
	$default['protocol'] = 'auto';
	$default['update_cert'] = FALSE;
	$default['update_dns'] = FALSE;

	$_POST += $default;
	$status_class = '';
	$chain = array();

	ob_start();
	{
		if($_POST['update_cert'])
		{
			$update_cert = ssl_fetch_cert($_POST['domain'], $_POST['port'], $_POST['protocol']);
		}

		$cert_meta = ssl_load_cert($_POST['domain'], $_POST['port']);

		if(!$cert_meta AND !$_POST['update_cert'])
		{
			$update_cert = ssl_fetch_cert($_POST['domain'], $_POST['port'], $_POST['protocol']);
			$cert_meta = ssl_load_cert($_POST['domain'], $_POST['port']);
		}

		$tlsa = dns_fetch_tls($_POST['domain'], $_POST['port']);

		if($cert_meta AND $cert_meta['cert'])
		{
			$cert_meta['sha512'] = openssl_x509_fingerprint($cert_meta['cert'], 'sha512');
			$cert_meta['sha1'] = openssl_x509_fingerprint($cert_meta['cert'], 'sha1');
			$cert_meta['md5'] = openssl_x509_fingerprint($cert_meta['cert'], 'md5');
			$cert_meta['parsed'] = openssl_x509_parse($cert_meta['cert']);
			$cert_meta['hex_only_content'] = str_replace("\n", "", substr($cert_meta['content'], strlen('-----BEGIN CERTIFICATE-----'), -strlen('-----END CERTIFICATE-----')));
			$cert_meta['pub_key'] = openssl_pkey_get_details(openssl_pkey_get_public($cert_meta['cert']))['key'];
			$cert_meta['pub_key_hex_only_content'] = str_replace("\n", "", substr($cert_meta['pub_key'], strlen('-----BEGIN PUBLIC KEY-----'), -strlen('-----END PUBLIC KEY-----')));
			$pub_key_raw_content = base64_decode($cert_meta['pub_key_hex_only_content']);
			$cert_meta['pub_key_sha256'] = hash('sha256', $pub_key_raw_content);
			$cert_meta['pub_key_sha512'] = hash('sha512', $pub_key_raw_content);

			$current = $cert_meta;
			$chain[] = $current;

			while($current['parent'])
			{
				$current = ssl_load_cert_sha256($current['parent']);
				if($current)
				{
					$current['sha512'] = openssl_x509_fingerprint($current['cert'], 'sha512');
					$current['hex_only_content'] = str_replace("\n", "", substr($current['content'], strlen('-----BEGIN CERTIFICATE-----'), -strlen('-----END CERTIFICATE-----')));
					$current['pub_key'] = openssl_pkey_get_details(openssl_pkey_get_public($current['cert']))['key'];
					$current['pub_key_hex_only_content'] = str_replace("\n", "", substr($current['pub_key'], strlen('-----BEGIN PUBLIC KEY-----'), -strlen('-----END PUBLIC KEY-----')));
					$pub_key_raw_content = base64_decode($current['pub_key_hex_only_content']);
					$current['pub_key_sha256'] = hash('sha256', $pub_key_raw_content);
					$current['pub_key_sha512'] = hash('sha512', $pub_key_raw_content);
					$chain[] = $current;
				}
			}
		}
	}
// 	echo "<pre>" . print_r(, 1) . "</pre>";
	$errors = ob_get_clean();

	if($tlsa)
	{
		$usages_list = array('CA constraint', 'Service certificate constraint', 'Trust anchor assertion', 'Domain-issued certificate');
		$selector_list = array('Full certificate', 'SubjectPublicKeyInfo');
		$matchingtype_list = array('No hash used', 'SHA-256', 'SHA-512');
		$tlsa['usage_text'] = isset($usages_list[$tlsa['usage']]) ? $usages_list[$tlsa['usage']] : '?';
		$tlsa['selector_text'] = isset($selector_list[$tlsa['selector']]) ? $selector_list[$tlsa['selector']] : '?';
		$tlsa['matchingtype_text'] = isset($matchingtype_list[$tlsa['matchingtype']]) ? $matchingtype_list[$tlsa['matchingtype']] : '?';

		if(!$cert_meta)
		{
			$tlsa['status'] = 'Unknown (certificate not loaded)';
		}
		else if($tlsa['usage'] != 3)
		{
			$tlsa['status'] = 'Unknown (usage type not supported yet)';
		}
		else if($tlsa['selector'] == 0)
		{
			if($tlsa['matchingtype'] == 1)
			{
				if(strtolower($tlsa['hash']) == $cert_meta['sha256'])
				{
					$tlsa['status'] = 'OK, sha256-hash matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, sha256-hash differ';
					$status_class = 'status_bad';
				}
			}
			else if($tlsa['matchingtype'] == 2)
			{
				if(strtolower($tlsa['hash']) == $cert_meta['sha512'])
				{
					$tlsa['status'] = 'OK, sha512-hash matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, sha512-hash differ';
					$status_class = 'status_bad';
				}
			}
			else if($tlsa['matchingtype'] == 0)
			{
				if($tlsa['hash'] == $cert_meta['hex_only_content'])
				{
					$tlsa['status'] = 'OK, content matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, content differ';
					$status_class = 'status_bad';
				}
			}
			else
			{
				$tlsa['status'] = 'Unknown (matchingtype type not supported yet)';
			}
		}
		else if($tlsa['selector'] == 1)
		{
			if($tlsa['matchingtype'] == 1)
			{
				if(strtolower($tlsa['hash']) == $cert_meta['pub_key_sha256'])
				{
					$tlsa['status'] = 'OK, sha256-hash matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, sha256-hash differ';
					$status_class = 'status_bad';
				}
			}
			else if($tlsa['matchingtype'] == 2)
			{
				if(strtolower($tlsa['hash']) == $cert_meta['pub_key_sha512'])
				{
					$tlsa['status'] = 'OK, sha512-hash matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, sha512-hash differ';
					$status_class = 'status_bad';
				}
			}
			else if($tlsa['matchingtype'] == 0)
			{
				if($tlsa['hash'] == $cert_meta['pub_key_hex_only_content'])
				{
					$tlsa['status'] = 'OK, content matches';
					$status_class = 'status_ok';
				}
				else
				{
					$tlsa['status'] = 'BAD, content differ';
					$status_class = 'status_bad';
				}
			}
			else
			{
				$tlsa['status'] = 'Unknown (matchingtype type not supported yet)';
			}
		}
		else
		{
			$tlsa['status'] = 'Unknown (selector type not supported yet)';
		}
	}
	else
	{
		$tlsa = array('usage' => NULL, 'selector' => NULL, 'matchingtype' => NULL, 'hash' => NULL, 'usage_text' => NULL, 'selector_text' => NULL, 'matchingtype_text' => NULL);
		$tlsa['status'] = 'No record';
	}

	$domain_html = htmlentities($_POST['domain']);
	$port_html = (int)  $_POST['port'];
	$protocol_options = html_options(array('auto' => 'guess from port', '' => 'pure ssl', 'smtp' => 'smtp'), $_POST['protocol']);
	$subject_html = htmlentities($cert_meta['parsed']['subject']['CN']);
	$issuer_html = htmlentities($cert_meta['parsed']['issuer']['CN']);
	$hash_html = chunk_split($tlsa['hash'], 64);
	$sha256_html = chunk_split($cert_meta['sha256'], 64);
	$sha512_html = chunk_split($cert_meta['sha512'], 64);
	$expire_date = gmdate("Y-m-d H:i:s", $cert_meta['parsed']['validTo_time_t']);
	$created_date = gmdate("Y-m-d H:i:s", $cert_meta['parsed']['validFrom_time_t']);
	$pule_date = gmdate("Y-m-d H:i:s", strtotime($cert_meta['pulse']));
	$export_html = htmlentities($cert_meta['content']);
	$pub_key_html = htmlentities($cert_meta['pub_key']);

	echo <<<HTML_BLOCK
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
	<head>
		<title>TLSA info of {$domain_html}:{$port_html}</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
		<style type='text/css'>
			BODY
			{
				font-size: 16px;
			}

			TABLE
			{
				border: solid gray 1px;
			}

			TH, TD
			{
				border: solid gray 1px;
				padding: 2px 5px;
				text-align: left;
				vertical-align: top;
			}

			TR
			{
				background-color: #EEE;
			}

			TR:nth-child(odd)
			{
				background-color: #DDD;
			}

			PRE.cert_export
			{
				background-color: #EEE;
				width: -moz-fit-content;
				padding: 5px;
			}

			TD.status_ok
			{
				color: green;
				font-weight: bold;
			}

			TD.status_bad
			{
				color: red;
				font-weight: bold;
			}

			LABEL > SPAN
			{
				display: inline-block;
				width: 70px;
			}

			INPUT[name="domain"]
			{
				width: 300px;
			}

			INPUT[name="port"]
			{
				width: 30px;
			}

			.hash
			{
				font-family: monospace;
				width: 600px;
			}
		</style>
	</head>
	<body>
		<form method='post' action='/'>
			<h1>TLSA info of {$domain_html}:{$port_html}</h1>
			<p>This page show information about SSL connections, and their TLSA records.</p>
			<fieldset>
				<label>
					<span>Domain:</span>
					<input name='domain' value='{$domain_html}' />
				</label><br />
				<label>
					<span>Port:</span>
					<input name='port' value='{$port_html}' />
				</label><br />
				<label>
				<label>
					<span>Protocol:</span>
					<select name='protocol'>
{$protocol_options}
					</select>
				</label><br />
				<label>
					<span></span>
					<input type='submit' value='Fetch' />
				</label><br />
			</fieldset>
{$errors}
			<h2>TLSA DNS record</h2>
			<p>The current TLSA DNS-record (you may also want to check the <a href='http://dnsviz.net/d/{$domain_html}/dnssec/'>DNSSEC status</a>)</p>
			<table>
				<tbody>
					<tr>
						<th>TLSA DNS target</th>
						<td>_{$port_html}._tcp.{$domain_html}</td>
					</tr>
					<tr>
						<th>Cert. Usage</th>
						<td>{$tlsa['usage']}: {$tlsa['usage_text']}</td>
					</tr>
					<tr>
						<th>Selector</th>
						<td>{$tlsa['selector']}: {$tlsa['selector_text']}</td>
					</tr>
					<tr>
						<th>Matching Type</th>
						<td>{$tlsa['matchingtype']}: {$tlsa['matchingtype_text']}</td>
					</tr>
					<tr>
						<th>Hash</th>
						<td class='hash'>{$hash_html}</td>
					</tr>
					<tr>
						<th>Status</th>
						<td class='{$status_class}'>{$tlsa['status']}</td>
					</tr>
				</tbody>
			</table>
			<!-- p><input type='submit' name='update_dns' value='Update DNS cache' /></p -->

			<h2>TLSA sugestions</h2>
			<p>Valid TLSA DNS records sugestions</p>
			<table>
				<thead>
					<tr>
						<th>Target</th>
						<th>Usage</th>
						<th>Selector</th>
						<th>M-type</th>
						<th>Hash</th>
					</tr>
				</thead>
				<tbody>
HTML_BLOCK;

	foreach($chain as $current)
	{
		$cert_sha256_html = chunk_split($current['sha256'], 64);
		$cert_sha512_html = chunk_split($current['sha512'], 64);
		$pub_key_sha256_html = chunk_split($current['pub_key_sha256'], 64);
		$pub_key_sha512_html = chunk_split($current['pub_key_sha512'], 64);
		$hex_only_content_length = strlen($current['hex_only_content']);
		$hex_only_content_rows = ceil($hex_only_content_length / 64);
		$hex_only_content_html_part = substr($current['hex_only_content'], 0, 64) . "<br/>...(" . ($hex_only_content_rows - 2) . " more rows)...<br/>" . substr($current['hex_only_content'], $hex_only_content_rows*64 - 64);
		$pub_key_content_html = chunk_split($current['pub_key_hex_only_content'], 64);

		$usage = '2?';
		if(!$current['parent']) $usage = '0?';
		$usage = '?';
		if($current['sha256'] == $cert_meta['sha256']) $usage = 3;

		echo <<<HTML_BLOCK
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>0</td>
						<td>1</td>
						<td class='hash'>{$cert_sha256_html}</td>
					</tr>
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>1</td>
						<td>1</td>
						<td class='hash'>{$pub_key_sha256_html}</td>
					</tr>
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>0</td>
						<td>2</td>
						<td class='hash'>{$cert_sha512_html}</td>
					</tr>
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>1</td>
						<td>2</td>
						<td class='hash'>{$pub_key_sha512_html}</td>
					</tr>
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>1</td>
						<td>0</td>
						<td class='hash'>{$pub_key_content_html}</td>
					</tr>
					<tr>
						<td>_{$port_html}._tcp.{$domain_html}</td>
						<td>{$usage}</td>
						<td>0</td>
						<td>0</td>
						<td class='hash'>{$hex_only_content_html_part}</td>
					</tr>
HTML_BLOCK;
	}
	echo <<<HTML_BLOCK
				</tbody>
			</table>
			<h2>SSL Cert</h2>
			<p>The current certificate at the given connetion</p>
			<table>
				<tbody>
					<tr>
						<th>Domain/Subject</th>
						<td>{$subject_html}</th>
					</tr>
					<tr>
						<th>Fingerprint SHA256</th>
						<td class='hash'>{$sha256_html}</td>
					</tr>
					<tr>
						<th>Fingerprint SHA512</th>
						<td class='hash'>{$sha512_html}</td>
					</tr>
					<tr>
						<th>Fingerprint SHA1</th>
						<td class='hash'>{$cert_meta['sha1']}</td>
					</tr>
					<tr>
						<th>Fingerprint MD5</th>
						<td class='hash'>{$cert_meta['md5']}</td>
					</tr>
					<tr>
						<th>Issuer</th>
						<td>{$issuer_html}</td>
					</tr>
					<tr>
						<th>Expires</th>
						<td>{$expire_date} Z</td>
					</tr>
					<tr>
						<th>Created</th>
						<td>{$created_date} Z</td>
					</tr>
				</tbody>
			</table>
			<p>certificate fetched at {$pule_date} Z <input type='submit' name='update_cert' value='Update SSL cache' /></p>
			<h3>Certificate at {$domain_html}:{$port_html}</h3>
			<pre class='cert_export'>{$export_html}</pre>
			<h3>Public key at {$domain_html}:{$port_html}</h3>
			<pre class='cert_export'>{$pub_key_html}</pre>
		</form>
	</body>
</html>
HTML_BLOCK;
