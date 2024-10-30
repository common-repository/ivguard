<?php
/*
Plugin Name: IVGuard
Plugin URI: https://ivguard.net
Description: IVGuard is one of the most powerful protection and monitoring services for WordPress. You will be informed immediately for any changes and discrepancies in your website and our team will be always on standby to help you resolve any security threats. Have full control of your website once and for all.
Author: Ignite Vision Ltd
Version: 1.2.3
Author URI: http://www.ignitevision.bg
*/
defined('ABSPATH') or exit(0);

if(class_exists('IVGuard')) {
	add_action('admin_notices', function() {
		echo '<div class="notice notice-error"><p><strong>WARNING!</strong><br>IVGuard cannot be started. Same class already exist in your WordPress.</p></div>';
	});
} else {
	register_activation_hook(__FILE__, array('IVGuard', 'onActivation'));
	register_uninstall_hook(__FILE__, array('IVGuard', 'onUninstall'));
	add_action('init', array('IVGuard', 'init'));
	add_action('plugins_loaded', array('IVGuard', 'onLoaded'));
	add_action('template_redirect', array('IVGuard', 'processRequest'));
	add_action('admin_menu', array('IVGuard', 'adminMenu'));
	add_action('wp_login_failed', array('IVGuard', 'onLoginFail'));
	add_action('login_form', array('IVGuard', 'onLoginForm'));
	add_action('password_reset', array('IVGuard', 'onPasswordReset'), 10, 2);
	add_action('admin_post_ivguard_settings', array('IVGuard', 'setSettings'));
	add_filter('login_redirect', array('IVGuard', 'onLoginRedirect'), 10, 3);
	add_filter('authenticate', array('IVGuard', 'onAuthenticate'), 30, 3);

	final class IVGuard {
		const CRAWLER = 'crawler.ivguard.net';
		const APIKEY = 'ivGuardKey';
		const API_VERIFY_IP = 'ivGuardAPIVerifyIP';
		const ALLOWED_IPS_KEY = 'ivGuardAllowedIPs';
		const WEBSITE = 'https://ivguard.net/';
		const API = 'https://dashboard.ivguard.net/api/';
		const OS_WIN = 'win';
		const OS_NIX = 'nix';
		const DB_KEY = 'ivGuardDbVersion';
		const DB_VERSION = '1.2';
		const DB_TABLE_BLOCKED = 'ivguard_blocked_ip';
		const DB_TABLE_CANDIDATE_BLOCKING = 'ivguard_candidate_blocking';
		const DB_TABLE_LOGIN_FAIL = 'ivguard_login_fail';
		const MAX_LOGIN_ATTEMPTS = 6;
		const BAN_LOGIN_TIME = 24;
		const MASSIVE_BRUTE_FORCE_KEY = 'ivGuardMassiveBruteForce';
		const MASSIVE_BRUTE_FORCE_MAX_LOGIN_ATTEMPTS = 3;
		const MASSIVE_BRUTE_FORCE_TIME_INTERVAL = 3;
		const MASSIVE_BRUTE_FORCE_BAN_TIME = 3;

		public static function onActivation() {
			global $wpdb;
			if(!get_option(IVGuard::APIKEY))
				add_option(IVGuard::APIKEY, md5((rand(999, 9999) * rand(666, 6666)) + time()));

			if(!get_option(IVGuard::API_VERIFY_IP))
				add_option(IVGuard::API_VERIFY_IP, 1);

			if(!function_exists('dbDelta'))
				require_once(ABSPATH.DIRECTORY_SEPARATOR.'wp-admin'.DIRECTORY_SEPARATOR.'includes'.DIRECTORY_SEPARATOR.'upgrade.php');

			$charsetCollate = $wpdb->get_charset_collate();

			// ---

			$blockedIPs = $wpdb->prefix.IVGuard::DB_TABLE_BLOCKED;
			$sql = 'CREATE TABLE `'.$blockedIPs.'` (
				`ip` VARCHAR(64) NOT NULL,
				`note` VARCHAR(255) NULL,
				`createdOn` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
			) '.$charsetCollate.';';
			dbDelta($sql);

			if(!IVGuard::indexExists($blockedIPs, 'PRIMARY'))
				$wpdb->query('ALTER TABLE `'.$blockedIPs.'` ADD PRIMARY KEY (`ip`)');

			$indexName = $wpdb->prefix.'ivguardBlockedIPsCreatedOn';
			if(!IVGuard::indexExists($blockedIPs, $indexName))
				$wpdb->query('CREATE INDEX `'.$indexName.'` ON `'.$blockedIPs.'` (`createdOn`)');

			// ---

			$candidateBlocking = $wpdb->prefix.IVGuard::DB_TABLE_CANDIDATE_BLOCKING;
			$sql = 'CREATE TABLE `'.$candidateBlocking.'` (
				`ip` VARCHAR(64) NOT NULL,
				`createdOn` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			) '.$charsetCollate.';';
			dbDelta($sql);

			if(!IVGuard::indexExists($candidateBlocking, 'PRIMARY'))
				$wpdb->query('ALTER TABLE `'.$candidateBlocking.'` ADD PRIMARY KEY (`ip`, `createdOn`)');

			// ---

			$loginFail = $wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL;
			$sql = 'CREATE TABLE `'.$loginFail.'` (
				`ip` VARCHAR(64) NOT NULL,
				`attempts` INT(3) UNSIGNED NOT NULL DEFAULT "1",
				`user_id` BIGINT(20) UNSIGNED NULL,
				`code` CHAR(6) DEFAULT NULL,
				`createdOn` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
			) '.$charsetCollate.';';
			dbDelta($sql);

			if(!IVGuard::indexExists($loginFail, 'PRIMARY'))
				$wpdb->query('ALTER TABLE `'.$loginFail.'` ADD PRIMARY KEY (`ip`)');

			$indexName = $wpdb->prefix.'ivguardLoginFailCreatedOn';
			if(!IVGuard::indexExists($loginFail, $indexName))
				$wpdb->query('CREATE INDEX `'.$indexName.'` ON `'.$loginFail.'` (`createdOn`)');

			$indexName = $wpdb->prefix.'ivguardLoginFailUserId';
			if(!IVGuard::indexExists($loginFail, $indexName))
				$wpdb->query('CREATE INDEX `'.$indexName.'` ON `'.$loginFail.'` (`user_id`)');

			// ---

			if(get_option(IVGuard::DB_KEY)) {
				update_option(IVGuard::DB_KEY, IVGuard::DB_VERSION);
			} else {
				add_option(IVGuard::DB_KEY, IVGuard::DB_VERSION);
			}
		}

		public static function onUninstall() {
			global $wpdb;
			$wpdb->query('DROP TABLE IF EXISTS `'.$wpdb->prefix.IVGuard::DB_TABLE_BLOCKED.'`');
			$wpdb->query('DROP TABLE IF EXISTS `'.$wpdb->prefix.IVGuard::DB_TABLE_CANDIDATE_BLOCKING.'`');
			$wpdb->query('DROP TABLE IF EXISTS `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'`');
			delete_option(IVGuard::APIKEY);
			delete_option(IVGuard::API_VERIFY_IP);
			delete_option(IVGuard::MASSIVE_BRUTE_FORCE_KEY);
		}

		public static function onLoaded() {
			if(IVGuard::DB_VERSION != get_option(IVGuard::DB_KEY))
				IVGuard::onActivation();
		}

		public static function adminMenu() {
			add_menu_page('IVGuard', 'IVGuard', 'manage_options', 'ivguard', array('IVGuard', 'settingsPage'), IVGuard::getLogo());
		}

		public static function settingsPage() {
			global $wp_version;
			wp_enqueue_script('script', 'https://cdn.jsdelivr.net/clipboard.js/1.5.12/clipboard.min.js');
			$activationCode = base64_encode(json_encode(array(
				'type' => 'WordPress',
				'version' => $wp_version,
				'url' => get_site_url(),
				'path' => rtrim(rtrim(ABSPATH, '/'), '\\'),
				'key' => get_option(IVGuard::APIKEY),
				'os' => IVGuard::detectOS()
			)));
			echo '<div class="wrap">';
			echo '	<h1>IVGuard</h1>';
			echo '	<div class="welcome-panel" style="background-color:rgba(255,255,255,.5)">';
			echo '		<h2>Activation</h2>';
			echo '		<hr>';
			echo '		<p style="font-size:1.1em">';
			echo '			To start the monitoring process copy the following code, and paste it in the Activation Code field on the "Secure Site" Tab. Remember you must be registered and logged in <a target="_blank" href="'.IVGuard::WEBSITE.'">'.IVGuard::WEBSITE.'</a> before you proceed with this step.';
			echo '			<br><br><b>Never share this activation code with anyone else</b>';
			echo '		</p>';
			echo '		<label for="activationCode">Activation Code:</label>';
			echo '		<textarea id="activationCode" style="width:100%" readonly>' . $activationCode . '</textarea>';
			echo '		<p style="text-align:center"><button data-clipboard-target="#activationCode" class="button">Copy To Clipboard</button></p>';
			echo '	</div>';
			echo '	<div class="welcome-panel" style="background-color:rgba(255,255,255,.5)">';
			echo '		<h2>Settings</h2>';
			echo '		<hr>';
			echo '		<label for="apiVerifyIp">Enable requests behind proxy</label>';
			echo '		<select id="apiVerifyIp" name="apiVerifyIp">';
			echo '			<option value="1">No</option>';
			echo '			<option value="0"'.(get_option(IVGuard::API_VERIFY_IP, 1) == 0 ? ' selected' : null).'>Yes</option>';
			echo '		</select>';
			echo '		<p style="font-size:1.1em">If your website is running behind a proxy like CloudFlare or this is not your IP address <b>'.$_SERVER['REMOTE_ADDR'].'</b> you need to set this option to "Yes".</p>';
			echo '	</div>';
			echo '</div>';
			echo '<script>';
			echo 'jQuery(function() {';
			echo '	jQuery("body").css({"background-image":"url('.IVGuard::getLogo().')","background-size":"80%","background-repeat":"no-repeat","background-position":"center 10vh","background-attachment":"fixed"});';
			echo '	new Clipboard("button[data-clipboard-target]");';
			echo '	jQuery("select#apiVerifyIp").on("change", function() {';
			echo '		jQuery.post("'.admin_url('admin-post.php').'", {action: "ivguard_settings", '.IVGuard::API_VERIFY_IP.': jQuery(this).val()});';
			echo '	});';
			echo '})';
			echo '</script>';
		}

		public static function setSettings() {
			if(array_key_exists(IVGuard::API_VERIFY_IP, $_POST) && in_array($_POST[IVGuard::API_VERIFY_IP], array(0, 1)))
				update_option(IVGuard::API_VERIFY_IP, $_POST[IVGuard::API_VERIFY_IP]);
		}

		public static function getInfo() {
			global $wp_version;
			if(!function_exists('get_plugins'))
				require_once(ABSPATH.DIRECTORY_SEPARATOR.'wp-admin'.DIRECTORY_SEPARATOR.'includes'.DIRECTORY_SEPARATOR.'plugin.php');

			$response = array(
				'wordpress' => array(
					'info' => array(
						'url' => get_site_url(),
						'path' => rtrim(rtrim(ABSPATH, '/'), '\\'),
						'version' => $wp_version,
						'content' => trim(mb_substr(WP_CONTENT_DIR, mb_strlen(ABSPATH)), DIRECTORY_SEPARATOR),
						'themes' => trim(mb_substr(get_theme_root(), mb_strlen(ABSPATH)), DIRECTORY_SEPARATOR),
						'plugins' => trim(mb_substr(WP_PLUGIN_DIR, mb_strlen(ABSPATH)), DIRECTORY_SEPARATOR),
						'os' => IVGuard::detectOS()
					),
					'plugins' => IVGuard::getPlugins(),
					'themes' => IVGuard::getThemes(),
					'users' => IVGuard::getUsers()
				)
			);
			return $response;
		}

		public static function getFiles($offset = 0, $limit = -1) {
			$files = array();
			$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH), RecursiveIteratorIterator::SELF_FIRST);
			$regex = new RegexIterator($iterator, '/^.+\.(php|html|js|htaccess)$/i', RecursiveRegexIterator::GET_MATCH);
			$os = IVGuard::detectOS();
			$absLen = mb_strlen(ABSPATH);
			foreach(new LimitIterator($regex, $offset, $limit) as $path) {
				if(!is_file($path[0]))
					continue;
				$webPath = trim(mb_substr($path[0], $absLen), DIRECTORY_SEPARATOR);
				if($os == IVGuard::OS_WIN)
					$webPath = str_replace(DIRECTORY_SEPARATOR, '/', $webPath);
				$files[$webPath] = md5_file($path[0]);
			}
			return $files;
		}

		public static function getFile($file) {
			$response = array('success' => false);
			try {
				if(!file_exists($file))
					throw new Exception('The file does not exist ('.$file.')', 404);
				if(($data = file_get_contents($file)) === false)
					throw new Exception('The file is not readable ('.$file.')', 403);
				$response = array('success' => true, 'data' => base64_encode($data));
			} catch(Exception $e) {
				$response['error'] = $e->getMessage();
				$response['errorCode'] = $e->getCode();
			}
			return $response;
		}

		public static function setFile($file, $data) {
			$response = array('success' => false);
			try {
				if(file_exists($file)) {
					if(!is_writable($file))
						throw new Exception('The file is not writable ('.$file.')');
				} else {
					$dir = dirname($file);
					if(!is_dir($dir))
						mkdir($dir, 0755, true);
				}
				if(file_put_contents($file, base64_decode($data)) === false)
					throw new Exception('The file cannot be saved ('.$file.')');
				$response['success'] = true;
			} catch(Exception $e) {
				$response['error'] = $e->getMessage();
			}
			return $response;
		}

		public static function getPlugins() {
			$slug = array();
			$os = IVGuard::detectOS();
			$updateOption = get_site_transient('update_plugins');
			if(is_array($updateOption)) {
				foreach($updateOption as $attr => $object) {
					if(!in_array($attr, array('response', 'no_update')))
						continue;
					foreach($object as $file => $plugin) {
						if($os == IVGuard::OS_WIN)
							$file = str_replace(DIRECTORY_SEPARATOR, '/', $file);
						$slug[$file] = $plugin->slug;
					}
				}
			}

			$activePlugins = get_option('active_plugins');
			$plugins = array();
			foreach(get_plugins() as $file => $plugin) {
				if($os == IVGuard::OS_WIN)
					$file = str_replace(DIRECTORY_SEPARATOR, '/', $file);
				foreach($plugin as $key => $val) {
					$plugins[$file][strtolower($key)] = $val;
				}
				$plugins[$file]['slug'] = array_key_exists($file, $slug) ? $slug[$file] : null;
				$plugins[$file]['active'] = in_array($file, $activePlugins) ? 'Yes' : 'No';
			}
			return $plugins;
		}

		public static function getThemes() {
			$activeTheme = wp_get_theme();
			$os = IVGuard::detectOS();
			$themes = array();
			foreach(wp_get_themes() as $key => $_theme) {
				$theme = wp_get_theme($key);
				$dir = rtrim(mb_substr($theme->get_template_directory(), mb_strlen(get_theme_root())), DIRECTORY_SEPARATOR);
				if($os == IVGuard::OS_WIN)
					$dir = str_replace(DIRECTORY_SEPARATOR, '/', $dir);
				$themes[$key] = array(
					'name' => $theme->name,
					'version' => $theme->version,
					'dir' => $dir,
					'active' => $activeTheme->template == $theme->template ? 'Yes' : 'No'
				);
			}
			return $themes;
		}

		public static function getUsers() {
			$users = array();
			foreach(get_users(array('orderby' => 'ID', 'order' => 'ASC')) as $user) {
				$users[$user->ID] = array(
					'id' => $user->ID,
					'username' => $user->data->user_login,
					'email' => $user->data->user_email,
					'password' => md5($user->data->user_pass),
					'roles' => $user->roles,
					'isAdmin' => is_super_admin($user->ID)
				);
			}
			return $users;
		}

		public static function getBlockedIPs($search = null, $limit = 20, $offset = 0) {
			global $wpdb;
			$rows = $wpdb->get_results(
				$wpdb->prepare('
					SELECT
						`ip`,
						`note`,
						`createdOn`
					FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_BLOCKED.'`
					WHERE (`ip` = %s OR %s = "")
					ORDER BY `createdOn` DESC, `ip` ASC
					LIMIT %d OFFSET %d
				', array($search, $search, $limit, $offset))
			);
			$total = $wpdb->get_var($wpdb->prepare(
				'SELECT COUNT(`ip`) FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_BLOCKED.'` WHERE (`ip` = %s OR %s = "")',
				array($search, $search)
			));
			$results = array(
				'rows' => $rows,
				'total' => $total
			);
			if($wpdb->last_error !== '')
				$results = array('error' => $wpdb->last_error);
			return $results;
		}

		public static function getBlockedLogin($search = null, $limit = 20, $offset = 0) {
			global $wpdb;
			$rows = $wpdb->get_results($wpdb->prepare('
				SELECT
					`ip`,
					`code`,
					`user_id`,
					`attempts`,
					`createdOn`
				FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'`
				WHERE (`ip` = %s OR `user_id` = %s OR %s = "") AND `attempts` > %d
				ORDER BY `createdOn` DESC, `ip` ASC LIMIT %d OFFSET %d',
				array($search, $search, $search, IVGuard::MAX_LOGIN_ATTEMPTS, $limit, $offset)
			));
			$total = $wpdb->get_var($wpdb->prepare(
				'SELECT COUNT(`ip`) FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'` WHERE (`ip` = %s OR `user_id` = %s OR %s = "")',
				array($search, $search, $search)
			));
			$results = array(
				'rows' => $rows,
				'total' => $total
			);
			if($wpdb->last_error !== '')
				$results = array('error' => $wpdb->last_error);
			return $results;
		}

		public static function init() {
			IVGuard::isBlockedIP();
			IVGuard::registerQueryParam();
		}

		public static function registerQueryParam() {
			add_rewrite_tag('%ivGuard%', '([^&]+)');
			add_rewrite_tag('%options%', '([^&]+)');
			add_rewrite_tag('%data%', '([^&]+)');
		}

		public static function authorize() {
			if(get_option(IVGuard::API_VERIFY_IP, 1) != 0) {
				if(!in_array($_SERVER['REMOTE_ADDR'], IVGuard::getAllowedIPs()))
					throw new Exception('Unauthorized actions have been detected! [BAD IP]');
			}
			if(!($ivGuardKey = get_option(IVGuard::APIKEY)))
				throw new Exception('Unauthorized actions have been detected! [NO KEY]');
			if(!isset($_POST['ivGuardKey']) || $_POST['ivGuardKey'] != $ivGuardKey)
				throw new Exception('Unauthorized actions have been detected! [BAD KEY]');
		}

		public static function getAllowedIPs() {
			if(($data = get_option(IVGuard::ALLOWED_IPS_KEY))) {
				if(!is_array($data = json_decode($data, true)) || !array_key_exists('expire', $data) || !array_key_exists('allowedIPs', $data) || $data['expire'] < time())
					$data = false;
			}
			if(!$data) {
				$allowedIPs = dns_get_record(IVGuard::CRAWLER, DNS_A + DNS_AAAA);
				if(!is_array($allowedIPs) || empty($allowedIPs))
					throw new Exception('Unable to get a list with allowed IP addresses! [DNS Error]');
				array_walk($allowedIPs, function(&$item, $key) { $item = $item['type'] == 'A' ? $item['ip'] : $item['ipv6']; });
				$data = array('expire' => time() + 300, 'allowedIPs' => $allowedIPs);
				update_option(IVGuard::ALLOWED_IPS_KEY, json_encode($data));
			}
			return $data['allowedIPs'];
		}

		public static function processRequest() {
			ini_set('display_errors', 0);
			if($ivGuard = get_query_var('ivGuard')) {
				$response = array('success' => true);
				try {
					IVGuard::authorize();
					$options = json_decode(base64_decode(get_query_var('options', 'W10=')), true);
					switch($ivGuard) {
						case 'getInfo':
							$response = IVGuard::getInfo();
							break;
						case 'getFiles':
							if(!isset($options['offset']) || !isset($options['limit']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::getFiles($options['offset'], $options['limit']);
							break;
						case 'getFile':
							if(!isset($options['file']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::getFile($options['file']);
							break;
						case 'setFile':
							if(!isset($options['file']) || !isset($_POST['data']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::setFile($options['file'], $_POST['data']);
							break;
						case 'exec':
							if(is_string($options[0]) && !function_exists($options[0])) {
								throw new Exception('Unknown Function');
							} elseif(is_array($options[0]) && !method_exists($options[0][0], $options[0][1])) {
								throw new Exception('Unknown Method');
							}
							$response['data'] = call_user_func_array($options[0], $options[1]);
							break;
						case 'getBlockedIPs':
							if(!isset($options['limit']) || !isset($options['offset']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::getBlockedIPs($options['search'], $options['limit'], $options['offset']);
							break;
						case 'unblockIP':
							if(!isset($options['ip']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::unblockIP($options['ip']);
							break;
						case 'blockIP':
							if(!isset($options['ip']) || !isset($options['note']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::blockIP($options['ip'], $options['note']);
							break;
						case 'changePassword':
							if(!isset($options['userId']) || !isset($options['password']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::changePassword($options['userId'], $options['password']);
							break;
						case 'getBlockedLogin':
							if(!isset($options['limit']) || !isset($options['offset']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::getBlockedLogin($options['search'], $options['limit'], $options['offset']);
							break;
						break;
						case 'unblockLogin':
							if(!isset($options['ip']))
								throw new Exception('Parameter mismatch');
							$response = IVGuard::unblockLogin($options['ip']);
							break;
						default:
							throw new Exception('Unknown command');
					}
				} catch(Exception $e) {
					$response = array('success' => false, 'error' => $e->getMessage());
				}
				wp_send_json($response);
			} else {
				IVGuard::detect404();
			}
		}

		public static function detectOS() {
			return DIRECTORY_SEPARATOR == '/' ? IVGuard::OS_NIX : IVGuard::OS_WIN;
		}

		public static function detect404() {
			global $wp;
			global $wp_query;
			global $wpdb;

			if($wp_query->is_404()) {
				if(!preg_match('/.+\.(jpg|jpeg|png|gif|ico|svg|css|less|js|woff|woff2|eot|ttf|swf|mp4|flv|ogg|webm|mp3|wav)$/i', $wp->request)) {
					$wpdb->replace($wpdb->prefix.IVGuard::DB_TABLE_CANDIDATE_BLOCKING, array('ip' => $_SERVER['REMOTE_ADDR']), array('%s'));
					$requests = $wpdb->get_var('
						SELECT
							COUNT(*)
						FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_CANDIDATE_BLOCKING.'`
						WHERE `ip` = "'.$_SERVER['REMOTE_ADDR'].'" AND `createdOn` >= DATE_SUB(NOW(), INTERVAL 60 SECOND)
					');
					if($requests >= 20)
						IVGuard::blockIP($_SERVER['REMOTE_ADDR'], 'Too many 404 errors, possible scan for bad software.');
				}
			}
		}

		public static function isBlockedIP() {
			global $wpdb;
			$result = $wpdb->get_var('SELECT `ip` FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_BLOCKED.'` WHERE `ip` = "'.$_SERVER['REMOTE_ADDR'].'" LIMIT 1');
			if($result) {
				wp_die('<div style="text-align:center"><img src="https://ivguard.net/images/protected-by-ivguard.png" alt="Protected by IVGuard"><br>Your IP address <strong>'.$_SERVER['REMOTE_ADDR'].'</strong> is blocked!<br><a href="'.IVGuard::WEBSITE.'faq#blocked-ip" target="_blank">Read more</a></div>', 'Forbidden', 403);
			}
		}

		public static function unblockIP($ip) {
			global $wpdb;
			return $wpdb->delete($wpdb->prefix.IVGuard::DB_TABLE_BLOCKED, array('ip' => $ip), array('%s'));
		}

		public static function blockIP($ip, $note) {
			global $wpdb;
			$wpdb->query($wpdb->prepare('DELETE FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_CANDIDATE_BLOCKING.'` WHERE `createdOn` < DATE_SUB(NOW(), INTERVAL 60 SECOND) OR `ip` = %s', $ip));
			return $wpdb->replace($wpdb->prefix.IVGuard::DB_TABLE_BLOCKED, array('ip' => $ip, 'note' => $note), array('%s', '%s'));
		}

		public static function unblockLogin($id) {
			global $wpdb;
			if(is_numeric($ip)) {
				$response = $wpdb->delete($wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL, array('user_id' => $id), array('%d'));
			} else {
				$response = $wpdb->delete($wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL, array('ip' => $id), array('%s'));
			}
			return $response;
		}

		public static function isUnderMassiveBruteForce() {
			$isUnderAttack = false;
			if($underAttack = get_option(IVGuard::MASSIVE_BRUTE_FORCE_KEY)) {
				$underAttack = json_decode($underAttack);
				if($underAttack->createdOn >= (time() - (IVGuard::MASSIVE_BRUTE_FORCE_BAN_TIME * 60 * 60)))
					$isUnderAttack = true;
			}
			return $isUnderAttack;
		}

		public static function getMassiveBruteForceCode() {
			if($underAttack = get_option(IVGuard::MASSIVE_BRUTE_FORCE_KEY)) {
				$underAttack = json_decode($underAttack);
				return $underAttack->code;
			}
			return null;
		}

		public static function onLoginFail($username) {
			global $wpdb;
			$ip = $_SERVER['REMOTE_ADDR'];
			$attempts = $wpdb->get_var($wpdb->prepare('SELECT `attempts` FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'` WHERE `ip` = %s LIMIT 1', $ip));
			if(is_null($attempts)) {
				$wpdb->insert($wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL, array('ip' => $ip, 'attempts' => 1), array('%s', '%d'));
			} elseif(IVGuard::MAX_LOGIN_ATTEMPTS == $attempts) {
				$userId = null;
				$code = wp_generate_password(6, false, false);
				if(($user = WP_User::get_data_by('login', $username)) || ($user = WP_User::get_data_by('email', $username))) {
					$userId = $user->ID;
					IVGuard::request('bruteforce/send-login-security-code', array('name' => $user->user_login, 'email' => $user->user_email, 'ip' => $ip, 'code' => $code));
				}
				$wpdb->update(
					$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL,
					array('attempts' => $attempts + 1, 'user_id' => $userId, 'code' => $code),
					array('ip' => $ip),
					array('%d', '%d', '%s'),
					array('%s')
				);
				$attempts = $wpdb->get_var($wpdb->prepare('
					SELECT
						COUNT(*)
					FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'`
					WHERE `createdOn` >= DATE_SUB(NOW(), INTERVAL %d MINUTE) AND `attempts` >= %d
				', array(IVGuard::MASSIVE_BRUTE_FORCE_TIME_INTERVAL, IVGuard::MAX_LOGIN_ATTEMPTS)));
				if(IVGuard::MASSIVE_BRUTE_FORCE_MAX_LOGIN_ATTEMPTS <= $attempts) {
					if(!IVGuard::isUnderMassiveBruteForce()) {
						$underAttack = array(
							'createdOn' => time(),
							'code' => wp_generate_password(rand(8,10), false, false)
						);
						update_option(IVGuard::MASSIVE_BRUTE_FORCE_KEY, json_encode($underAttack));
						IVGuard::request('bruteforce/massive-brute-force-attack', array('code' => $underAttack['code']));
					}
				}
			} else {
				$wpdb->update($wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL, array('attempts' => $attempts + 1), array('ip' => $ip), array('%d'), array('%s'));
			}
		}

		public static function onLoginForm() {
			global $wpdb;

			$isUnderMassiveBruteForce = IVGuard::isUnderMassiveBruteForce();

			$ip = $_SERVER['REMOTE_ADDR'];
			$loginFail = $wpdb->get_row($wpdb->prepare('
				SELECT
					`attempts`,
					`user_id`
				FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'`
				WHERE `ip` = %s AND `createdOn` >= DATE_SUB(NOW(), INTERVAL '.IVGuard::BAN_LOGIN_TIME.' HOUR)
			', $ip));

			if($isUnderMassiveBruteForce || (!is_null($loginFail) && $loginFail->attempts > IVGuard::MAX_LOGIN_ATTEMPTS)) {
				echo '<p>';
				echo '<label for="ivguard_security_code">IVGuard Security Code<br>';
				echo '<input type="text" class="input" name="ivguard_security_code" id="ivguard_security_code">';
				if($isUnderMassiveBruteForce) {
					$message = 'Massive brute-force attack detected. To continue please enter your username, password and master security code<br><a href="'.IVGuard::WEBSITE.'faq#massive-brute-force-attack" target="_blank">Read more</a>';
				} elseif(is_null($loginFail->user_id)) {
					$message = 'Too many attempts with an unknown username. Due to security reasons your IP address '.$ip.' is blocked for '.IVGuard::BAN_LOGIN_TIME.' hours.<br><a href="'.IVGuard::WEBSITE.'faq#unblock-login" target="_blank">Read more</a>';
				} else {
					$user = get_userdata($loginFail->user_id);
					$message = 'Too many attempts with an incorrect password, to continue please enter your password and the security code that was sent to '.IVGuard::hideEmail($user->user_email).'<br><a href="'.IVGuard::WEBSITE.'faq#unblock-login" target="_blank">Read more</a>';
				}
				echo '<div style="text-align:center;color:red;margin-bottom:1em">'.$message.'</div>';
				echo '</p>';
			}
		}

		public static function onLoginRedirect($redirectTo, $request, $user) {
			global $wpdb;
			if($user instanceof WP_User)
				IVGuard::unblockLogin($_SERVER['REMOTE_ADDR']);
			return $redirectTo;
		}

		public static function onAuthenticate($user, $username, $password) {
			global $wpdb;
			if($username == '')
				return $user;

			$codes = array();
			if(IVGuard::isUnderMassiveBruteForce())
				$codes[] = IVGuard::getMassiveBruteForceCode();

			$code = $wpdb->get_var($wpdb->prepare('
				SELECT
					`code`
				FROM `'.$wpdb->prefix.IVGuard::DB_TABLE_LOGIN_FAIL.'`
				WHERE `ip` = %s AND `createdOn` >= DATE_SUB(NOW(), INTERVAL '.IVGuard::BAN_LOGIN_TIME.' HOUR)
			', $_SERVER['REMOTE_ADDR']));
			if(!is_null($code))
				$codes[] = $code;

			if(!empty($codes)) {
				if(!array_key_exists('ivguard_security_code', $_POST) || !in_array($_POST['ivguard_security_code'], $codes)) {
					$user = new WP_Error();
					$user->add('invalid_ivguard_security_code', "<strong>Error</strong>: Invalid IVGuard Security Code");
					add_action('login_head', 'wp_shake_js', 12);
				}
			}
			return $user;
		}

		public static function onPasswordReset($user, $pass) {
			IVGuard::unblockLogin($_SERVER['REMOTE_ADDR']);
		}

		public static function changePassword($userId, $password) {
			IVGuard::unblockLogin($userId);
			wp_set_password($password, $userId);
			return true;
		}

		public static function request($url, $data) {
			wp_remote_request(IVGuard::API.$url, array(
				'method' => 'POST',
				'blocking' => false,
				'headers' =>  array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json'
				),
				'body' => json_encode(array(
					'url' => get_site_url(),
					'key' => get_option(IVGuard::APIKEY),
					'data' => $data
				))
			));
		}

		public static function hideEmail($email) {
			return preg_replace('/(?:^|@).\K|\.[^@]*$(*SKIP)(*F)|.(?=.*?\.)/', '*', $email);
		}

		public static function indexExists($tableName, $indexName) {
			global $wpdb;
			return !is_null($wpdb->get_row($wpdb->prepare('SHOW INDEX FROM `'.$tableName.'` WHERE `Key_name` = %s', array($indexName))));
		}

		public static function getLogo() {
			return 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/Pgo8IURPQ1RZUEUgc3ZnIFBVQkxJQyAiLS8vVzNDLy9EVEQgU1ZHIDIwMDEwOTA0Ly9FTiIKICJodHRwOi8vd3d3LnczLm9yZy9UUi8yMDAxL1JFQy1TVkctMjAwMTA5MDQvRFREL3N2ZzEwLmR0ZCI+CjxzdmcgdmVyc2lvbj0iMS4wIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciCiB3aWR0aD0iOTkzLjAwMDAwMHB0IiBoZWlnaHQ9IjExODQuMDAwMDAwcHQiIHZpZXdCb3g9IjAgMCA5OTMuMDAwMDAwIDExODQuMDAwMDAwIgogcHJlc2VydmVBc3BlY3RSYXRpbz0ieE1pZFlNaWQgbWVldCI+CjxnIHRyYW5zZm9ybT0idHJhbnNsYXRlKDAuMDAwMDAwLDExODQuMDAwMDAwKSBzY2FsZSgwLjEwMDAwMCwtMC4xMDAwMDApIgpmaWxsPSIjRkZGRkZGIiBzdHJva2U9Im5vbmUiPgo8cGF0aCBkPSJNNDg5NyAxMTU4NSBjLTc1IC02OSAtMjI2IC0xODggLTM2MCAtMjg0IC0xMDQzIC03NDYgLTI1NjYgLTEyNTQKLTQzMzMgLTE0NDYgbC02MiAtNyAtNyAtMTc2IGMtOSAtMTk3IC0xIC03MDAgMTUgLTk3NyA4OCAtMTUzMCA0MzMgLTI5ODAKMTAzMiAtNDM0MCA1NTIgLTEyNTAgMTQyNCAtMjUyNiAyMjA4IC0zMjI5IDQyNiAtMzgyIDg1NyAtNjc3IDEzNTggLTkyOCBsMjAyCi0xMDIgMjAzIDEwMSBjODc2IDQzOSAxNTU2IDEwMTcgMjIyNyAxODkxIDg0OSAxMTA4IDE1MDAgMjQxNyAxOTA2IDM4MzIgMjU0Cjg4NSAzOTggMTczOCA0NjUgMjczNSAxNCAyMTMgMjQgMTE3NCAxMyAxMTg1IC01IDUgLTc1IDE3IC0xNTQgMjUgLTIyNyAyNQotNjEyIDgyIC04NzggMTMxIC0xNTE0IDI3NiAtMjgwOSA4MTggLTM2NTkgMTUzMSAtNjcgNTcgLTEyNCAxMDMgLTEyNSAxMDMgLTIKLTEgLTI1IC0yMSAtNTEgLTQ1eiBtLTIzNzcgLTI4NTQgYzE0IC0yOCAxMyAtMTgzIC0yIC0yMDQgLTEyIC0xNCAtNjAgLTE2Ci00NzggLTE5IC02MjggLTQgLTU4NSAyMSAtNTg1IC0zNDMgMCAtMjYyIDUgLTI4MiA4MCAtMzIwIDM4IC0xOSA2MCAtMjAgMzcxCi0yMCA0MDYgMCAzNzYgLTEyIDM3MiAxNDQgbC0zIDEwNiAtMjYwIDUgLTI2MCA1IDAgOTUgMCA5NSAzNjkgMyBjMjY0IDIgMzczCi0xIDM4MiAtOSAxMSAtOSAxNCAtNjMgMTQgLTI2NCAwIC0zMTUgLTkgLTM0OCAtMTAyIC0zOTYgLTM1IC0xOCAtNjUgLTE5Ci00NTYgLTE5IC00MjcgMCAtNDk1IDUgLTU3NyA0MCAtMTAwIDQzIC0xNjUgMTQwIC0xODUgMjc2IC0xMyA4OSAtMTMgNDM5IDAKNTI5IDEyIDc4IDQzIDE1NCA4NCAyMDIgMzIgMzggMTMxIDg5IDE5NiAxMDIgMjUgNSAyNjYgOSA1MzcgMTAgNDc3IDEgNDkzIDAKNTAzIC0xOHogbTQ2MCAtMzg2IGM1IC0zNzkgNiAtNDAyIDI1IC00MzUgMTIgLTE5IDM4IC00NCA2MCAtNTUgMzcgLTE5IDYwCi0yMCAzNTAgLTIwIDMyOSAwIDM2MiA0IDQwMyA0OCAzOCA0MSA0MiA4OCA0MiA0NzIgMCAyMDQgNCAzNzYgOCAzODMgNyA5IDM5CjEyIDEyOCAxMCBsMTE5IC0zIDAgLTQzMCBjMCAtMzc5IC0yIC00MzcgLTE3IC00ODYgLTMyIC0xMDMgLTExMCAtMTgyIC0yMTIKLTIxNiAtNDMgLTE0IC0xMDggLTE4IC00MjYgLTIxIC0zODggLTMgLTQ2NSAyIC01NDYgMzggLTk3IDQyIC0xNjIgMTM4IC0xODMKMjcwIC0xMiA2OSAtMTUgODA3IC01IDgzNCA1IDE0IDI0IDE2IDEyOCAxNCBsMTIxIC0zIDUgLTQwMHogbTIxMDQgMzkxIGMxOAotNyA0NiAtMzAgNjIgLTQ5IDQ5IC02MCA1OTggLTEwNzcgNTg3IC0xMDg4IC02IC02IC02MyAtOCAtMTM4IC03IGwtMTI5IDMKLTYwIDExMiAtNjEgMTEzIC0zODUgMCAtMzg1IC0xIC02MCAtMTEyIC02MCAtMTEyIC0xMzcgLTMgYy0xMTUgLTIgLTEzOCAwCi0xMzggMTIgMCAxNiA1MjUgOTk0IDU2OSAxMDYxIDQ4IDcyIDc5IDg1IDE5OCA4NSA2NSAwIDExNiAtNSAxMzcgLTE0eiBtMTg3OAotMiBjNzIgLTIwIDEzNyAtNzUgMTY4IC0xNDAgNTAgLTEwOCA0NyAtMzYzIC02IC00NzEgLTMwIC02MiAtODYgLTEwOCAtMTUxCi0xMjYgLTI0IC02IC00MyAtMTQgLTQzIC0xNyAwIC0zIDY0IC04NSAxNDEgLTE4MyA4NyAtMTEwIDEzOSAtMTgzIDEzNSAtMTkyCi00IC0xMiAtMzEgLTE1IC0xNDEgLTE1IGwtMTM1IDAgLTEzNyAxODUgLTEzOCAxODQgLTI2MiAxIC0yNjMgMCAtMiAtMTgyIC0zCi0xODMgLTExNSAtMyBjLTk5IC0yIC0xMTYgMCAtMTI3IDE1IC0xNiAyMSAtMTkgMTA3NiAtMyAxMTE3IGwxMCAyNiA1MDcgMApjNDM5IDAgNTE1IC0yIDU2NSAtMTZ6IG0xNDAyIDEgYzE0OSAtMzIgMjQ2IC0xMTUgMjg5IC0yNTAgMjAgLTY0IDIyIC04OSAyMgotMzE1IDAgLTIyNiAtMiAtMjUxIC0yMiAtMzE1IC0zMCAtOTQgLTgyIC0xNjAgLTE1OSAtMjAyIC0xMDggLTU5IC0xNDcgLTYzCi02NjIgLTYzIGwtNDYyIDAgLTEwIDI2IGMtMTMgMzQgLTEzIDEwNzQgMCAxMTA4IGwxMCAyNiA0NjIgMCBjMzY2IDAgNDc3IC0zCjUzMiAtMTV6IG0tNTcyNCAtMTI4MyBjMCAtNSA2NiAtMTE5IDE0NiAtMjUzIDgxIC0xMzQgMTU2IC0yNjAgMTY2IC0yNzkgMjAKLTM0IDkwIC0xNDkgMTQ3IC0yNDAgMTYgLTI1IDIxMyAtMzUzIDQzOSAtNzMwIDIyNSAtMzc3IDQ3NCAtNzkxIDU1MiAtOTIwIDc4Ci0xMjkgMTQ1IC0yNDIgMTQ4IC0yNTAgMyAtOCAzMSAtNTggNjIgLTExMCAzMiAtNTIgMTc4IC0yOTcgMzI1IC01NDUgMTQ3Ci0yNDcgMzM2IC01NjUgNDIwIC03MDUgMTY1IC0yNzYgMjkzIC00OTMgMzExIC01MjUgNiAtMTEgNTIgLTg5IDEwMyAtMTcyIDUwCi04NCA5OCAtMTY4IDEwNiAtMTg3IDE5IC00NSAxOSAtMTU0IDAgLTE5OSAtOCAtMTkgLTc2IC0xMjYgLTE1MiAtMjM4IC03NgotMTEyIC0xNjUgLTI0NCAtMTk3IC0yOTIgLTMzIC00OCAtNzAgLTk3IC04NCAtMTA4IC0zOSAtMzEgLTEyNyAtNTIgLTE4MCAtNDQKLTUyIDggLTEzMSA0NiAtMTYwIDc5IC0xMSAxMSAtMTc2IDI3NyAtMzY3IDU5MSAtMTkxIDMxNCAtNDI3IDcwMSAtNTI1IDg2MAotMjY5IDQ0MCAtNDc4IDc4NSAtOTkzIDE2NDUgLTI1OCA0MzIgLTU5NyA5OTcgLTc1MiAxMjU1IC01MjMgODczIC03MzIgMTIyOAotNzUxIDEyNzkgLTYgMTcgLTQgMTggMjAgMTIgNzggLTE5IDIwNSAtMjUgNTQ1IC0yNiAzNDIgMCAzODEgMiA0NjEgMjAgNTkgMTQKMTAyIDMyIDEzNiA1NSA0OSAzNCA3NCA0MyA3NCAyN3ogbTE0MjggLTU2IGMyMCAtMTMgNjUgLTMwIDEwMCAtMzcgMzQgLTcgNjIKLTE3IDYyIC0yMyAwIC01IDEwIC0yMyAyMyAtNDAgMjQgLTMyIDE3OSAtMjg5IDIzMCAtMzgwIDE1IC0yOCAzNCAtNTcgNDEgLTY2CjggLTggMjcgLTQwIDQzIC03MCAxNyAtMzAgNDYgLTgyIDY2IC0xMTUgMjAgLTMzIDU0IC04OCA3NCAtMTIzIDIxIC0zNSA2NAotMTA0IDk2IC0xNTMgMzEgLTQ5IDU3IC05MiA1NyAtOTUgMCAtNCAyMCAtMzcgNDUgLTc0IDI1IC0zNyA0NSAtNzIgNDUgLTc2IDAKLTUgMTggLTM1IDQwIC02NyAyMiAtMzEgNDAgLTYxIDQwIC02NiAwIC02IDIwIC0zOSA0NSAtNzUgMjUgLTM3IDQ1IC03MCA0NQotNzQgMCAtNSAyNyAtNDkgNjAgLTEwMCAzMyAtNTAgNjAgLTk1IDYwIC0xMDAgMCAtNSAxMyAtMjcgMjggLTQ4IDE1IC0yMSA0MgotNjQgNTggLTk0IDE3IC0zMCA1NSAtOTMgODQgLTE0MCAyOSAtNDcgNjcgLTExMCA4NSAtMTQwIDQxIC03MCA4OCAtMTQ5IDEzNwotMjI2IDIxIC0zMyAzOCAtNjUgMzggLTcwIDAgLTYgMTMgLTI4IDMwIC01MCAxNiAtMjEgMzAgLTQ1IDMwIC01MSAxIC0zOSA2NgozMiA5MyAxMDEgNCAxMiAyMyA0NCA0MSA3MSA1MCA3NiAxNDEgMjI5IDE5MiAzMjEgMTIgMjMgMzMgNTkgNDcgODAgNDcgNzUKMTA3IDE4MCAxMDcgMTg4IDAgNCAxMSAyMiAyNCAzOSAxMyAxOCAzNiA1NSA1MSA4MiAxNSAyOCAzNyA2MyA0OCA3OSAxMiAxNwoyOCA0NCAzNyA2MCA0MSA3OCA4MCAxNDUgMTE0IDE5NiAyMCAzMCAzNiA1OCAzNiA2MyAwIDUgMTQgMjggMzAgNTIgMTcgMjQgMzAKNDggMzAgNTMgMCA1IDEzIDI3IDI5IDUwIDE3IDIyIDQzIDY0IDU5IDk0IDMzIDYwIDg2IDE1MCAxMTQgMTkwIDEwIDE1IDIzIDM5CjI4IDUyIDUgMTQgMjUgNDggNDUgNzUgMTkgMjggMzUgNTYgMzUgNjIgMCA1IDExIDI1IDI0IDQyIDEzIDE4IDM0IDUyIDQ2IDc3CjEzIDI1IDMzIDU5IDQ1IDc1IDEyIDE3IDMyIDUwIDQ0IDc1IDEzIDI1IDMwIDUyIDM4IDYxIDggMTAgMjggNDMgNDQgNzUgMTcKMzMgMzcgNjYgNDUgNzUgOCA4IDE0IDIxIDE0IDI3IDAgMTYgNjggMTEwIDgzIDExNSA3IDIgMzkgLTIgNzIgLTEwIDQ4IC0xMQoxNTAgLTEzIDUyMCAtMTAgNDg5IDQgNDgwIDMgNjg1IDYwIDggMiAxMiAyIDcgMCAtNCAtMyAtNyAtMTIgLTcgLTIyIDAgLTkgLTQKLTIxIC05IC0yNyAtOSAtOCAtNTEgLTgwIC0xMDYgLTE3OSAtMjcgLTQ4IC02NyAtMTE4IC0xNjUgLTI4NSAtNDAgLTY5IC04NAotMTQ1IC05NyAtMTcwIC0xNCAtMjQgLTMzIC01NyAtNDQgLTcxIC0xMCAtMTUgLTE5IC0zMCAtMTkgLTM0IDAgLTQgLTI5IC01NgotNjUgLTExNiAtMzYgLTU5IC02NSAtMTExIC02NSAtMTE0IDAgLTQgLTEzIC0yNiAtMzAgLTUwIC0xNiAtMjQgLTM0IC01NCAtMzkKLTY3IC01IC0xMyAtMjEgLTM4IC0zNSAtNTcgLTE0IC0xOSAtMjYgLTQwIC0yNiAtNDYgMCAtNyAtMTQgLTMxIC0zMCAtNTMgLTE3Ci0yMyAtMzAgLTQ3IC0zMCAtNTMgMCAtNiAtMTMgLTI5IC0yOCAtNTIgLTE2IC0yMyAtMzYgLTU1IC00NCAtNzIgLTggLTE2IC0zNwotNjYgLTY0IC0xMTAgLTI4IC00NCAtNTcgLTk0IC02NiAtMTEwIC0yNyAtNTIgLTg3IC0xNTYgLTEwNyAtMTg0IC0xMSAtMTQKLTMwIC00NyAtNDMgLTcxIC0yMyAtNDMgLTQ5IC05MCAtMTEzIC0yMDUgLTE1IC0yNyAtMzMgLTU3IC00MCAtNjUgLTcgLTggLTE5Ci0yOCAtMjcgLTQ1IC0yNyAtNTEgLTcwIC0xMjcgLTEzMyAtMjMxIC0zMiAtNTQgLTU3IC05OSAtNTUgLTEwMCAzIDAgLTcgLTE3Ci0yMiAtMzcgLTE2IC0xOSAtMjggLTM5IC0yOCAtNDMgMCAtNCAtMjEgLTQxIC00NyAtODMgLTI3IC00MiAtNTMgLTg1IC01OQotOTYgLTYgLTExIC0yMiAtNDAgLTM2IC02NSAtMTMgLTI1IC0zNiAtNjQgLTUxIC04NyAtMTUgLTI0IC0yNyAtNDUgLTI3IC00OAowIC00IC0xMyAtMjUgLTI4IC00OCAtMTUgLTIzIC0zMyAtNTMgLTQwIC02NyAtMTIgLTI1IC0zNSAtNjUgLTEyMiAtMjE0IC0yNQotNDIgLTU3IC05OCAtNzIgLTEyNCAtMTUgLTI2IC00MCAtNjkgLTU0IC05NyAtMTQgLTI3IC0zMiAtNTcgLTM5IC02NSAtNyAtOAotMjQgLTM1IC0zOCAtNjAgLTEzIC0yNSAtNDEgLTc0IC02MiAtMTEwIC0yMSAtMzYgLTQ5IC04NSAtNjIgLTExMCAtMTQgLTI0Ci0zMyAtNTcgLTQ0IC03MSAtMTAgLTE1IC0xOSAtMjkgLTE5IC0zMiAwIC02IC0zMSAtNTggLTEwMCAtMTcyIC0yMCAtMzMgLTU1Ci05MiAtNzggLTEzMCAtODQgLTE0MiAtMTg5IC0yMTUgLTI5NyAtMjA2IC02OSA2IC0xODQgOTggLTIzMCAxODMgLTE1IDI5IC0zOAo2NyAtNTAgODMgLTEyIDE3IC0zMiA1MCAtNDUgNzUgLTEzIDI1IC00NSA3OCAtNzEgMTE4IC0yNyA0MCAtNDkgNzcgLTQ5IDgwIDAKNCAtMjAgMzggLTQ1IDc1IC0yNSAzOCAtNDUgNzEgLTQ1IDc0IDAgNyAtNjUgMTE1IC0xMDcgMTc4IC0xOCAyOCAtMzMgNTQgLTMzCjU4IDAgNSAtMTggMzUgLTQwIDY3IC0yMiAzMyAtNDUgNjkgLTUwIDgyIC02IDEzIC0yOCA1MCAtNTAgODMgLTIyIDMzIC00MyA2NwotNDcgNzUgLTMgOCAtMjggNDkgLTU1IDkxIC0yNiA0MiAtNDggNzkgLTQ4IDgzIDAgNCAtMTggMzQgLTQwIDY2IC0yMiAzMiAtNDAKNjMgLTQwIDY3IDAgNCAtMjMgNDIgLTUwIDgzIC0yNyA0MSAtNTAgNzkgLTUwIDgzIDAgNCAtMTcgMzQgLTM4IDY1IC0yMSAzMQotNDEgNjUgLTQ1IDc1IC00IDkgLTI0IDQzIC00NSA3NSAtMjEgMzEgLTQxIDY1IC00NSA3NSAtNCA5IC0yNCA0MyAtNDUgNzUKLTIxIDMxIC00MSA2NSAtNDUgNzUgLTQgOSAtMjUgNDQgLTQ3IDc3IC0yMiAzMiAtNDAgNjMgLTQwIDY3IDAgNCAtMTggMzUgLTQwCjY4IC0yMiAzMyAtNDAgNjMgLTQwIDY3IDAgNCAtMjIgNDIgLTUwIDg0IC0yNyA0MiAtNTAgODEgLTUwIDg2IDAgNSAtMTggMzMKLTQwIDYzIC0yMiAzMCAtNDAgNTkgLTQwIDY0IDAgNSAtMTcgMzYgLTM4IDY4IC0yMSAzMiAtNDEgNjYgLTQ1IDc2IC00IDkgLTI0CjQzIC00NSA3NSAtMjEgMzEgLTQxIDY1IC00NSA3NSAtNCA5IC0yNSA0NCAtNDcgNzcgLTIyIDMyIC00MCA2MyAtNDAgNjggMCA0Ci0yMCAzOCAtNDUgNzUgLTI1IDM3IC00NSA3MCAtNDUgNzMgMCAzIC0xNCAyNyAtMzEgNTMgLTE4IDI1IC00MyA2NiAtNTcgOTEKLTEzIDI1IC00NCA3NCAtNjcgMTEwIC0yMyAzNiAtNDUgNzMgLTQ4IDgzIC00IDkgLTI1IDQ0IC00NyA3NyAtMjIgMzIgLTQwIDYyCi00MCA2NiAwIDQgLTE2IDMzIC0zNiA2MyAtNDUgNzEgLTEzNSAyMjIgLTE0MSAyMzkgLTMgNyAtMjUgNDMgLTQ5IDc5IC0yNCAzNwotNDQgNzIgLTQ0IDc4IC0xIDUgLTE0IDI2IC0zMCA0NSAtMTcgMTkgLTMwIDM4IC0zMCA0MyAwIDUgLTIxIDQwIC00NiA3OSAtMjUKMzkgLTUwIDgxIC01NCA5MyBsLTggMjIgNjEgLTE2IGM1MiAtMTMgMTI3IC0xNiA0NDcgLTE2IGwzODUgMCAxMDQgMjggYzU4IDE1CjEwNyAyOSAxMDkgMzIgOCA4IDEwIDcgNTAgLTE5eiIvPgo8cGF0aCBkPSJNNDk0MyA4NDk4IGMtMTIgLTE2IC0yMzkgLTQzNiAtMjQ4IC00NjEgLTcgLTE2IDEwIC0xNyAyNjggLTE3IGwyNzUKMCAtMTMyIDI0MiBjLTcyIDEzMyAtMTM3IDI0MyAtMTQyIDI0NSAtNiAyIC0xNiAtMiAtMjEgLTl6Ii8+CjxwYXRoIGQ9Ik02MTQzIDg1MTQgYy0xMCAtNCAtMTMgLTUwIC0xMyAtMTgwIGwwIC0xNzUgMzQzIDMgYzM4MCAzIDM5MSA1IDQxOAo3MCAxOCA0MyAxOCAxNzMgMCAyMTYgLTI3IDY1IC0zOSA2NyAtNDA2IDY5IC0xODEgMSAtMzM2IDAgLTM0MiAtM3oiLz4KPHBhdGggZD0iTTc2MjIgODUxMiBjLTkgLTYgLTEyIC04MyAtMTAgLTM0OCBsMyAtMzM5IDMyNSAwIDMyNSAwIDQ5IDI1IGM5Mwo0NyAxMDYgODQgMTA2IDMyMCAwIDIzNiAtMTMgMjczIC0xMDYgMzIwIC00OSAyNSAtNTEgMjUgLTM2NCAyOCAtMTczIDEgLTMyMQotMSAtMzI4IC02eiIvPgo8L2c+Cjwvc3ZnPgo=';
		}
	}
}
