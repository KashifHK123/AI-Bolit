<?php
///////////////////////////////////////////////////////////////////////////
// Version: SOME_VERSION
// Created and developed by Greg Zemskov, Revisium Company
// Email: audit@revisium.com, http://revisium.com/ai/

// Commercial usage is not allowed without a license purchase or written permission of the author
// Source code and signatures usage is not allowed

// Certificated in Federal Institute of Industrial Property in 2012
// http://revisium.com/ai/i/mini_aibolit.jpg

////////////////////////////////////////////////////////////////////////////
// Запрещено использование скрипта в коммерческих целях без приобретения лицензии.
// Запрещено использование исходного кода скрипта и сигнатур.
//
// По вопросам приобретения лицензии обращайтесь в компанию "Ревизиум": http://www.revisium.com
// audit@revisium.com
// На скрипт получено авторское свидетельство в Роспатенте
// http://revisium.com/ai/i/mini_aibolit.jpg
///////////////////////////////////////////////////////////////////////////
ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');

define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль	 

define('PASS', '????????????????');

//////////////////////////////////////////////////////////////////////////

if (isCli()) {
    if (strpos('--eng', $argv[$argc - 1]) !== false) {
        define('LANG', 'EN');
    }
} else {
    if (PASS == '????????????????') {
       die('Forbidden'); 
    }

    define('NEED_REPORT', true);
}

if (!defined('LANG')) {
    define('LANG', 'EN');
}

// put 1 for expert mode, 0 for basic check and 2 for paranoid mode
// установите 1 для режима "Обычное сканирование", 0 для быстрой проверки и 2 для параноидальной проверки (диагностика при лечении сайтов) 
define('AI_EXPERT_MODE', 1);

define('REPORT_MASK_DOORWAYS', 4);
define('REPORT_MASK_FULL', REPORT_MASK_DOORWAYS);

define('AI_HOSTER', 0);

define('AI_EXTRA_WARN', 0);

$defaults = array(
    'path' => dirname(__FILE__),
    'scan_all_files' => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
    'scan_delay' => 0, // delay in file scanning to reduce system load
    'max_size_to_scan' => '650K',
    'site_url' => '', // website url
    'no_rw_dir' => 0,
    'skip_ext' => '',
    'skip_cache' => false,
    'report_mask' => REPORT_MASK_FULL
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)) {
    define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array(
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml'
);
$g_SensitiveFiles  = array_merge(array(
    'php',
    'js',
    'json',
    'htaccess',
    'html',
    'htm',
    'tpl',
    'inc',
    'css',
    'txt',
    'sql',
    'ico',
    '',
    'susp',
    'suspected',
    'zip',
    'tar'
), $g_SuspiciousFiles);
$g_CriticalFiles   = array(
    'php',
    'htaccess',
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml',
    'susp',
    'suspected',
    'infected',
    'vir',
    'ico',
    'js',
    'json',  
    ''
);
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction';
$g_VirusFiles      = array(
    'js',
    'json', 
    'html',
    'htm',
    'suspicious'
);
$g_VirusEntries    = '<script|<iframe|<object|<embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles      = array(
    'js',
    'html',
    'htm',
    'suspected',
    'php',
    'phtml',
    'pht',
    'php7'
);
$g_PhishEntries    = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt    = array(
    'php',
    'php3',
    'php4',
    'php5',
    'php7',
    'pht',
    'html',
    'htm',
    'phtml',
    'shtml',
    'khtml',
    '',
    'ico',
    'txt'
);

if (LANG == 'RU') {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // RUSSIAN INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Отображать по _MENU_ записей\"";
    $msg2  = "\"Ничего не найдено\"";
    $msg3  = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
    $msg4  = "\"Нет файлов\"";
    $msg5  = "\"(всего записей _MAX_)\"";
    $msg6  = "\"Поиск:\"";
    $msg7  = "\"Первая\"";
    $msg8  = "\"Предыдущая\"";
    $msg9  = "\"Следующая\"";
    $msg10 = "\"Последняя\"";
    $msg11 = "\": активировать для сортировки столбца по возрастанию\"";
    $msg12 = "\": активировать для сортировки столбцов по убыванию\"";
    
    define('AI_STR_001', 'Отчет сканера <a href="https://revisium.com/ai/">AI-Bolit</a> v@@VERSION@@:');
    define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>.<p> Компания <a href="https://revisium.com/">"Ревизиум"</a> предлагает услугу превентивной защиты сайта от взлома с использованием уникальной <b>процедуры "цементирования сайта"</b>. Подробно на <a href="https://revisium.com/ru/client_protect/">странице услуги</a>. <p>Лучшее лечение &mdash; это профилактика.');
    define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
    define('AI_STR_004', 'Путь');
    define('AI_STR_005', 'Изменение свойств');
    define('AI_STR_006', 'Изменение содержимого');
    define('AI_STR_007', 'Размер');
    define('AI_STR_008', 'Конфигурация PHP');
    define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
    define('AI_STR_010', "Сканер AI-Bolit запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
    define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
    define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
    define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования. Подробнее смотрите в <a href="https://revisium.com/ai/faq.php">FAQ вопрос №10</a>.</div>');
    define('AI_STR_015', '<div class="title">Критические замечания</div>');
    define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
    define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
    define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
    define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
    define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
    define('AI_STR_021', 'Подозрение на вредоносный скрипт');
    define('AI_STR_022', 'Символические ссылки (symlinks)');
    define('AI_STR_023', 'Скрытые файлы');
    define('AI_STR_024', 'Возможно, каталог с дорвеем');
    define('AI_STR_025', 'Не найдено директорий c дорвеями');
    define('AI_STR_026', 'Предупреждения');
    define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
    define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
    define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
    define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
    define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
    define('AI_STR_032', 'Невидимые ссылки');
    define('AI_STR_033', 'Отображены только первые ');
    define('AI_STR_034', 'Подозрение на дорвей');
    define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
    define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
    define('AI_STR_037', 'Версии найденных CMS');
    define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
    define('AI_STR_039', 'Не найдено файлов больше чем %s');
    define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
    define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
    define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
    define('AI_STR_043', 'Использовано памяти при сканировании: ');
    define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
    define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
    define('AI_STR_050', 'Замечания и предложения по работе скрипта и не обнаруженные вредоносные скрипты присылайте на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<p>Также будем чрезвычайно благодарны за любые упоминания скрипта AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. Ссылочку можно поставить на <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>. <p>Если будут вопросы - пишите <a href="mailto:ai@revisium.com">ai@revisium.com</a>. ');
    define('AI_STR_051', 'Отчет по ');
    define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
    define('AI_STR_053', 'Много косвенных вызовов функции');
    define('AI_STR_054', 'Подозрение на обфусцированные переменные');
    define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
    define('AI_STR_056', 'Дробление строки на символы');
    define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.<br> Рекомендуем проверить сайт в режиме "Эксперт" или "Параноидальный". Подробно описано в <a href="https://revisium.com/ai/faq.php">FAQ</a> и инструкции к скрипту.');
    define('AI_STR_058', 'Обнаружены фишинговые страницы');
    
    define('AI_STR_059', 'Мобильных редиректов');
    define('AI_STR_060', 'Вредоносных скриптов');
    define('AI_STR_061', 'JS Вирусов');
    define('AI_STR_062', 'Фишинговых страниц');
    define('AI_STR_063', 'Исполняемых файлов');
    define('AI_STR_064', 'IFRAME вставок');
    define('AI_STR_065', 'Пропущенных больших файлов');
    define('AI_STR_066', 'Ошибок чтения файлов');
    define('AI_STR_067', 'Зашифрованных файлов');
    define('AI_STR_068', 'Подозрительных (эвристика)');
    define('AI_STR_069', 'Символических ссылок');
    define('AI_STR_070', 'Скрытых файлов');
    define('AI_STR_072', 'Рекламных ссылок и кодов');
    define('AI_STR_073', 'Пустых ссылок');
    define('AI_STR_074', 'Сводный отчет');
    define('AI_STR_075', 'Сканер бесплатный только для личного некоммерческого использования. Информация по <a href="https://revisium.com/ai/faq.php#faq11" target=_blank>коммерческой лицензии</a> (пункт №11). <a href="https://revisium.com/images/mini_aibolit.jpg">Авторское свидетельство</a> о гос. регистрации в РосПатенте №2012619254 от 12 октября 2012 г.');
    
    $tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
   <div class="thanx">
      Замечания и предложения по работе скрипта, а также не обнаруженные вредоносные скрипты вы можете присылать на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<br/>
      Также будем чрезвычайно благодарны за любые упоминания сканера AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. <br/>Ссылку можно поставить на страницу <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>.<br/> 
     <p>Получить консультацию или задать вопросы можно по email <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
	</div>
HTML_FOOTER;
    
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Подозрительные параметры времени изменения файла");
    define('AI_STR_078', "Подозрительные атрибуты файла");
    define('AI_STR_079', "Подозрительное местоположение файла");
    define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.<p>Для диагностического сканирования без ложных срабатываний мы разработали специальную версию <u><a href=\"https://revisium.com/ru/blog/ai-bolit-4-ISP.html\" target=_blank style=\"background: none; color: #303030\">сканера для хостинг-компаний</a></u>.");
    define('AI_STR_081', "Уязвимости в скриптах");
    define('AI_STR_082', "Добавленные файлы");
    define('AI_STR_083', "Измененные файлы");
    define('AI_STR_084', "Удаленные файлы");
    define('AI_STR_085', "Добавленные каталоги");
    define('AI_STR_086', "Удаленные каталоги");
    define('AI_STR_087', "Изменения в файловой структуре");
    
    $l_Offer = <<<OFFER
    <div>
	 <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Наш сканер обнаружил подозрительный или вредоносный код</b>.</div> 
	 <p>Возможно, ваш сайт был взломан. Рекомендуем срочно <a href="https://revisium.com/ru/order/#fform" target=_blank>проконсультироваться со специалистами</a> по данному отчету.</p>
	 <p><hr size=1></p>
	 <p>Рекомендуем также проверить сайт бесплатным <b><a href="https://rescan.pro/?utm=aibolit" target=_blank>онлайн-сканером ReScan.Pro</a></b>.</p>
	 <p><hr size=1></p>
         <div class="caution">@@CAUTION@@</div>
    </div>
OFFER;
    
    $l_Offer2 = <<<OFFER2
	   <b>Наши продукты:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="https://revisium.com/ru/products/antivirus_for_ispmanager/" target=_blank>Антивирус для ISPmanager Lite</a></b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/blog/revisium-antivirus-for-plesk.html" target=_blank>Антивирус для Plesk</a> Onyx 17.x</b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://cloudscan.pro/ru/" target=_blank>Облачный антивирус CloudScan.Pro</a> для веб-специалистов</b> &mdash; лечение сайтов в один клик</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/antivirus-server/" target=_blank>Антивирус для сервера</a></b> &mdash; для хостин-компаний, веб-студий и агентств.</li>
              </ul>  
	</div>
OFFER2;
    
} else {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ENGLISH INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Display _MENU_ records\"";
    $msg2  = "\"Not found\"";
    $msg3  = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
    $msg4  = "\"No files\"";
    $msg5  = "\"(total _MAX_)\"";
    $msg6  = "\"Filter/Search:\"";
    $msg7  = "\"First\"";
    $msg8  = "\"Previous\"";
    $msg9  = "\"Next\"";
    $msg10 = "\"Last\"";
    $msg11 = "\": activate to sort row ascending order\"";
    $msg12 = "\": activate to sort row descending order\"";
    
    define('AI_STR_001', 'AI-Bolit v@@VERSION@@ Scan Report:');
    define('AI_STR_002', '');
    define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
    define('AI_STR_004', 'Path');
    define('AI_STR_005', 'iNode Changed');
    define('AI_STR_006', 'Modified');
    define('AI_STR_007', 'Size');
    define('AI_STR_008', 'PHP Info');
    define('AI_STR_009', "Your password for AI-BOLIT is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
    define('AI_STR_010', "Open AI-BOLIT with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
    define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
    define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
    define('AI_STR_013', 'Scanned %s folders and %s files.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
    define('AI_STR_015', '<div class="title">Critical</div>');
    define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
    define('AI_STR_017', 'Shell scripts signatures not detected.');
    define('AI_STR_018', 'Javascript virus signatures detected:');
    define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
    define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
    define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
    define('AI_STR_022', 'Symlinks:');
    define('AI_STR_023', 'Hidden files:');
    define('AI_STR_024', 'Files might be a part of doorway:');
    define('AI_STR_025', 'Doorway folders not detected');
    define('AI_STR_026', 'Warnings');
    define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
    define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
    define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
    define('AI_STR_030', 'Reading error. Skipped.');
    define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
    define('AI_STR_032', 'List of invisible links:');
    define('AI_STR_033', 'Displayed first ');
    define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
    define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
    define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
    define('AI_STR_037', 'CMS found:');
    define('AI_STR_038', 'Large files (greater than %s! Skipped:');
    define('AI_STR_039', 'Files greater than %s not found');
    define('AI_STR_040', 'Files recommended to be remove due to security reason:');
    define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
    define('AI_STR_042', 'Writable folders not found');
    define('AI_STR_043', 'Memory used: ');
    define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
    define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
    define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script. Please email me: <a href=\"mailto:audit@revisium.com\">audit@revisium.com</a>.<p> Also I appriciate any reference to the script in your blog or forum posts. Thank you for the link to download page: <a href=\"https://revisium.com/aibo/\">https://revisium.com/aibo/</a>");
    define('AI_STR_051', 'Report for ');
    define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
    define('AI_STR_053', 'Function called by reference');
    define('AI_STR_054', 'Suspected for obfuscated variables');
    define('AI_STR_055', 'Suspected for $GLOBAL array usage');
    define('AI_STR_056', 'Abnormal split of string');
    define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
    define('AI_STR_058', 'Phishing pages detected:');
    
    define('AI_STR_059', 'Mobile redirects');
    define('AI_STR_060', 'Malware');
    define('AI_STR_061', 'JS viruses');
    define('AI_STR_062', 'Phishing pages');
    define('AI_STR_063', 'Unix executables');
    define('AI_STR_064', 'IFRAME injections');
    define('AI_STR_065', 'Skipped big files');
    define('AI_STR_066', 'Reading errors');
    define('AI_STR_067', 'Encrypted files');
    define('AI_STR_068', 'Suspicious (heuristics)');
    define('AI_STR_069', 'Symbolic links');
    define('AI_STR_070', 'Hidden files');
    define('AI_STR_072', 'Adware and spam links');
    define('AI_STR_073', 'Empty links');
    define('AI_STR_074', 'Summary');
    define('AI_STR_075', 'For non-commercial use only. In order to purchase the commercial license of the scanner contact us at ai@revisium.com');
    
    $tmp_str = <<<HTML_FOOTER
		   <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
		   </div>
		   <div class="thanx">
		      We're greatly appreciate for any references in the social medias, forums or blogs to our scanner AI-BOLIT <a href="https://revisium.com/aibo/">https://revisium.com/aibo/</a>.<br/> 
		     <p>Contact us via email if you have any questions regarding the scanner or need report analysis: <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
			</div>
HTML_FOOTER;
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Suspicious file mtime and ctime");
    define('AI_STR_078', "Suspicious file permissions");
    define('AI_STR_079', "Suspicious file location");
    define('AI_STR_081', "Vulnerable Scripts");
    define('AI_STR_082', "Added files");
    define('AI_STR_083', "Modified files");
    define('AI_STR_084', "Deleted files");
    define('AI_STR_085', "Added directories");
    define('AI_STR_086', "Deleted directories");
    define('AI_STR_087', "Integrity Check Report");
    
    $l_Offer = <<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
 <br/>Most likely the website has been compromised. Please, <a href="https://revisium.com/en/contacts/" target=_blank>contact web security experts</a> from Revisium to check the report or clean the malware.
 <p><hr size=1></p>
 Also check your website for viruses with our free <b><a href="http://rescan.pro/?en&utm=aibo" target=_blank>online scanner ReScan.Pro</a></b>.
</div>
<br/>
<div>
   Revisium contacts: <a href="mailto:ai@revisium.com">ai@revisium.com</a>, <a href="https://revisium.com/en/contacts/">https://revisium.com/en/home/</a>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;
    
    $l_Offer2 = '<b>Special Offers:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="http://ext.plesk.com/packages/b71916cf-614e-4b11-9644-a5fe82060aaf-revisium-antivirus">Antivirus for Plesk Onyx</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px"><font color=red></font><b><a href="https://www.ispsystem.com/addons-modules/revisium">Antivirus for ISPmanager Lite</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px">Professional malware cleanup and web-protection service with 6 month guarantee for only $99 (one-time payment): <a href="https://revisium.com/en/home/#order_form">https://revisium.com/en/home/</a>.</li>
              </ul>  
	</div>';
    
    define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template = <<<MAIN_PAGE
<html>
<head>
<!-- revisium.com/ai/ -->
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css" title="currentStyle">
	@import "https://cdn.revisium.com/ai/media/css/demo_page2.css";
	@import "https://cdn.revisium.com/ai/media/css/jquery.dataTables2.css";
</style>

<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/jquery.js"></script>
<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/datatables.min.js"></script>

<style type="text/css">
 body 
 {
   font-family: Tahoma;
   color: #5a5a5a;
   background: #FFFFFF;
   font-size: 14px;
   margin: 20px;
   padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #DAF2C1;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #F2F2F2;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
	font-weight: 100;
	background: #FF0090;
	padding: 2px 0px 2px 0px;
	width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}

.offer
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #F2F2F2;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}

.offer2
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #f6f5e0;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #CEE9EF;
}


.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri;
   font-size: 12px;
   margin: 10px 10px 10px 0px;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
  color: #FFF;
  font-weight: 700;
  text-decoration: none;
  padding: 2px;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0px 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0px 0px;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #F4F4F4;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 <div class="offer">
@@OFFER@@
 </div>

 <div class="offer2">
@@OFFER2@@
 </div> 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
	<div class="footer">
	@@FOOTER@@
	</div>
	
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
		"paging": true,
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending": $msg11,
				"sSortDescending": $msg12	
			}
		}

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending":  $msg11,
				"sSortDescending": $msg12	
			}
		},

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
    $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$g_Mnemo = array();

//BEGIN_SIG 27/02/2019 01:42:24
$g_DBShe = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$gX_DBShe = unserialize(gzinflate(/*1551220944*/base64_decode("bVX9b+I4EP1XvDn2oFIpCUmgpNvqKLDtXT9V2L1dVVVkEhOsOB9rO7Swuvvbzx67tFodv5A8j59n3htPcDTwop80ck9ENIyclKxwQrhzQiNPIf0gcr5XDUpwiepGIoyKNERCclpmOqavYo4jp17XYk0Y05CvoEE/cj6ldIMShoU4dZasSnK0lNuaeM7Z+5VUVvUvyFIWzplmCgx5MhrtyUMD8XC4hwYm8dvFFKfpViNDu4+u90HHJujzC5BpZKQQT6X5N1miuQ5DS9jsaSE8TyuxoWw3f2XwQI4wci5xkpNURaMxW+ElkdVXymWDTZQV5NaX+7M93zLOZcWL4RtjYPHrKmnEOzy0qb1WeaTkhQVd6ihycCnpG/vQshRbwMgLSQA/NpmY2u5ywKBoZakO6ji8QF2OuiswEsrWmRPUpJhVAu1wxpsdlbCsqw/VKa2CCIEzgk4R4SSLOamZapiO8zGcfOz3nUPkmL/XwIMT2K918VTuteociZx5jQuSts8+LTlY3dcaBW7kCCKTqsop6SBd0Q8WP5NljNOClnEjCC/VPgdZUi2gr2wlTBC66qyaMpG0KmPyQoUUHQcEiUGRgwPYoaUNVRp0hTpUxAlmDC+ZSt8EIVym6IM6CnOOtxY9bKVU6CjNb3m0E35geDqtmvBCoN+R+zJxXfcAnZ7uH39COHikqkspR727C9T7BrC2yB8oljJhTUo6rXg+e/g6e3hsXy4W9/EX9RaPL2a3i/aTOXZk2njJ3WfhwyX1tW+Bqqi9lrJOj5KqXLUP25t1pRR4fUtWme4h/aQAal5gt2fr6NW8SnpiK3q50piw3hYXuFdLrryNRVLVBMK1i31fCb7BrLOijMQZkbEilaTUgusY3zaSkveZU2nk7W0w78FyYFuwdXF9dz6+nj+2Y/WDJTAnhJ17Y9ragvavxhhUNdk7ZwRwaGOUormrpIB74Gvt+wrKCkxZVxSy7tLyiB1lVZUxoiQqIMxOCNVt3HWh5/2RvVlTPQng2oPkgR2V07dRGXg29BHdr5WUL1v0BLgdB49JlRK+M5gWyNcD8kO3+5suBCVFeuq0wPPxZDK7Xzio2zUjMLCz4OmRV02ZdtyDJ5A5CF+HCi3GUr4lpwXwlIhTzPMJJ8+fOSVlCuIEQ5N43mfM91OAbNlX+ZXn+0OARpbhcjy5mk3R+Xc0X9w93MD4da17N+qKqW+CEQXIQ89uu+FH87Xq6DUuv3mjAaz1zeCaEppijv+F7g99eyn+omWtRlpV7AAOTKxXDv1Eem4JYGjPvVLfnXnOm1pd7MqcO/h/mqGhmZAyo7tLbGiODcj9jV9mQWkIRgY8v1b1frn9E5IbuHbUckmTnJE/nJN//gM=")));
$g_FlexDBShe = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$gX_FlexDBShe = unserialize(gzinflate(/*1551220944*/base64_decode("zV0LW9vIkv0rhGEyEMC2JD8BBwiQhB0SskDuzN4oV1eWZFuDLGkkOTxC9rdvvVoP2ySQZPfbyQRsqbvV6q6uOnWqumNvGb3G1md/q7GdbjW7W8vminn1Wdtotr6Y6bM+/DVX4cdm8cFdN9fw2zr+cNeXt/0tDep2G1vLiZdNkxCvlxsx/wU/0iyxEi/27Ey1VCmzAX8dzw/UTSgeeCG2rUPbHW1ruf/ht+WPAzv12k3L9ZzI9fACFN2Gv/c8eO4x5ho2aUCTWntr2QnsNIWrf9jxQeA7l3ivCffa8DhzsOqHTjB1vTv5bUWh490l3t9TP8l/00UcDuzM58aG9uXWj7ewoRY21H58Q9Tpudba2BrMztAPPGvkZZYThZkXZqm5en72D+vt/psjrFuTuuau7WR+FPaxaOpnXvo0jFzbCu2J18f2OjjbMGMnkWNjwS2saG/e7m/+s7HZsz6umzU3cqYTeIRZ8649rNOVOv7QXH0SJ97ImtiZMzZX8Yn117Zz6blLg5u6j983zBWs04M6va3lFzdmur4/eZKQtKCoaXD1gN9h8+Im9rZoqiy6r8mDvE82C8Qu/Bzd+uEwsDMvv0IiFWWaQZVQTrRGj7ono+inlmMHgT0Iikr5yMK8DLPYgndz7tKbNPMmd+nYCwK+EoNkZONkehdHsRfexUnkWPhpraiP0rRLj0Z50nuz/YWRj2IcW75EJVG6eq2tZdt1LZjKzEvmO5aNPTW75YdtlMtYgyAawXhEsyVq67uqVyiAhg7jkVpXiZ/NjUL9k53Us0lMhVG+dJDW9GYS+OFlteA4mnh1KtahQUYZSFMvo0He24VpW311dHH37vT84u786OwfR2d3B6envx8f3Z0d/ef7I7j68vjk6HzN/IDNVcSMhPUjKZQIx8L1PXhw6S1I6GBsR7fT0IkmIHa0ZEUCpgMQgvxrRTtQbRE/6KFloTojhdIo5FgEpSTMpQVo/nJjh653TZU0UUN78N5OFF1iP7HQhIWda8y9Gt7I/AmULXRmt91sNKhNFFkdFrXnjCNYH1ghMmuXZg0/oVozd59TQRQww6DZGfh2aN5NfDc2765s+BGPo9CDXxEsv4xKN0WTD2HERP6c8SRyrbNCJ8Z2NhaRgS9eMoEPVJmkpluS5bmlN7vydJIdrVqlWgLFxoARp3EGKxDYjlce6ToormckYTrOd4vM0MQGXZcoI7RioXiZH8qr4NriMpU1+ZGawYlvG4uf+AiJJWuB8mK0KtNET/PDNAP1YkWX+SUqr4l5OY9tGNZ1lNrAyzyXbuKcN5ugAZLEvskH4FUUjQJl0JQ0nQfTJMYPVNGQ5bwz1p43G8bSyygZ+K7rhTt1uLLzZHNzKYsu2WYaKAI6DHh9tk3TJHE2WvJO8Ti26HrNXPGuMxY90P1BUH0nnGOts7U8udbN2jjKcODNGrwa3aX5bc+Mtno36sJGtTmaZZieIepUXkg8gTWzVi9+lK+voOlDsU2pBZzgFtrpFdfObJESGdRClYJg+6EdlAWkT0uq2RCdba4MpPLEbaFOxo7TswYMFpqaLL44SjKYx7Q+TMCKXkXJZT31nCmo1ps6aWMqjfNrUL+4DW57zmxTWcIhDRAGtNDWMIkm/cobWyyarDbp6uuLi3fWa5DaotxHnjP68pQbigLXS6pNDc0PGi+NJspGCybrakwv60TTEDX5Cuh9LzXXnpsrThRYt6Bb1pZoQC2wgaUC1AjKT7eFrwkr3Q9HxTI9Pzo/Pz59W+o0TpBll3tc3Aun2a2XICwp3acnoMQ1NdTSSwA34ClxlGIv4FNqfmiYJZHaMXdBjqkWSqJO/fJT1EdKB9qfQGDRBFIpFD8Nxv3Q/uS7sERfBDa8G91CuWp25LEu6rxCnP4q+rimMPFK6F2lPq3tFuEaeDguRmj1r3Qzi6KA5rpFUtRk8LRXBk/wPmDCioeQGmyRGEE3rMqw6fCjKJljN6phiDHJNWVeLp0AzskltNWUgmL+9sr4AMbXVyavRXMMgrLnh76F5h6Ll7Qfg1lckvnFjdJtHwX+/jr0iLZYm396Ic7DKeCliX9rs9Va/4Tqf10zaw36X6MqOMNtnd7zQaIGMwTSZX7MJRSkYkpz3SJsoecjoWQFEKCfIrLGdlLHDi0XALqTRckNVSPb0plV4eMZTZt943uu2dvKvuDCg7XoJe+TQHqbv8k4y+KtOslGW1NqYwiQCWasgjr64JJtz1zbWXBts0+O3GeUx5lbT/rKxxsknn25TSq7rYuOJwFeOFTU0SFUodXQVqDFXAEYnI8+a1gywWxxzQ9UuimSMGNC1j4r127dsl6+f3twARNukZvQJhtWAH5n7DmXlu04pKtQ3DcQ56Qp/Eq95BPVaeeWygetVzLmLijocBoEnluxVO2OAAl8bTJ60LhHH0CyfPMjIygAon+BhPCXCUBUe+TxlzEMh5eQDmiT2gF5u/DsN/DsN1F6YdONnuij/NGH//Q08pU6SqfE4F5BneXzcL953V2me5pAAlzyUZqV1sH5+dsZfdohsAlSe5SNQ99BdywY2CGiyXSdfDfuZMcoeWyH/9Q7dBFnp9MkZ/Z7nKaSfDgTN3coOy15uf1pBsjq2Z9xEIEB4xdvcz8G2I9Ro0G6q9MpdBfMQ7SjtUFCYJBxMjz8Ecnb4lD3RN2CgoMFjBUI9Rbmsn4Vb855Wms4NG8P4edX69nuhPVph9RBxZ0gax9PS056jrtJu1oV9K2clW5DIM1eoVjIPKB5XWNM7cdpYMOIp9KcJXCV6iu3WaiWWZDNXY+ng8B3rHE2CaiSnptZcZmVX1c0XpIrhy1d15CJAwMEf1CEAHlMSYC6TYEGdXpXswam2dxlT7gPgNH6y/GeZnZ62Y+DKSzSp/yr709GEzuEdZM8xfErfwc7kGJtYZu6LTGOJVeMOnxLuCAf2Nsc83Tb+Uo553W7Dn8+4tRWv1PhjirM8mSubeNvLKHUJQseFUZB68L4ZTexF7EEoCoh8aBZ61f0+BTGZAhYo9AyWOUO/oDvm9fDWtR6T9SVA1oVkZ3y6FbF813VNzRzDRUcd6fXEGHkQU0BodqJM67/PfWSG5kKcIWteDS0+2hTfjX2f9Vfwv9XV1dmbURuCDWkyZNz9VtxrnEQbNGA8mQ9B+QlFf9wL6tniH4CRB1YgB5YCudc+l5TZoe8zVUmu56z1zJfuCUon5xztr/Ekb3Yl5IH0SGXbItmmS05un0fOtEbMEvnJN69jpBXI1hiMCybn9DFS2Ch2wO63xWg5ySOoauVNO+7gh6k4j1pDvyQS+8GvArXGni3fQUOtIaa0QXMH74vgZvVRb7C+cHZ8bsLoga5JZzSFirxUjcSWD+eVxbGCs905Q284ZCwD7ehK5a4VChVfurCJiZpOIgyrm2IW1pmCi7enVgoBlyClAe0v7fLrofrD4fWFEZGPPd7VOOjRE1rkN1pEOQSVZw7LzyI5Rc4PD14/+bo7YV1dnp6UVm2uZAU6tWfgMaCZQcD5sPvCpbQGihkXZrs1I49RQ9WnjYEnTYG9T2JYL2jUpl7YkWfpET7zDymI8Zv3g6xOJLM8DTNrupHDyXpP1yOFdyWd+jX1sGvun6vcCy4l+Mnbp8YPFIrjyIZWdmWmCHkGFlSJvimqHRxIBvCxWlESqMhrD9UdXI1TfjJvd37Rjsb++nmc1KK/IYgt4n3iaur9VR4hJYdBAUFeQcfa+Yzc23HNJHiKfuUGhHPyKsxyCwNe4J0ehgx+8RlCcK1fhDCBQBl1ok4RgjMDbeEOjZX3ChRL98v43guRxoWkLRloYavajIA7FyoI8SQufLq5PTF/sl5aTrn2FU1szhab9+fnHATXXEQp+z3VdYPLlakvKaiNtfmVrD5oU43ua2e+DB7YNXA9mJHHZzJjSX4gOCwBr/z4sQsIzAxB2ydaP6rYRW+tmNPHK6ieGWQb1IE6HrRQpe1OHvxG8W4UV0FJGASfOZj/w5gNkYOLHdVhYsaAhrNX96nc3Zggc3hWopfnFwyQp4LFBCPjCWE4VtQQrli5soU3DMLVnyYWVlUxEVKjB7X6Ah3umCllciueuAPkJ2DNmppxDVJJtD0/fKkPvDDejoOHbfs/lXIsvODdyW0X3BV/pBb64nO++6lVBY4DIiuh9EVYglunwlnAyEEwQq8E5h39wAOjfnmgs16VrBZGtHNuOi8a/KtNt0BsbZKuXEhQ2ZisQYrjBtOHtdoCigRjxjl6Q18vIhyJf6Glfg5O8azl19E7g23RKYYmWV0hOipMvOoYi0Mjnrg2RbzK0TI3KpeiIDoAiGgxXypvD9KYgeU8JP7VLg7KJlMpdFhXRyjtT8K0Xa6F0ifl4tz20pmUwecN2jwA2HKUixrDuWKtBNH3tHRywldCzk8aV3Yh0KA3IqZU51ESqLoMXSOWyXeHFrtfydO14g5xxayaIr8ZUV5ruCbIKSq4/tFIY4hflQDyi1oAvUFvq9kkxjUCMhkmlpDx6wF0YgL6sKM0bwoqkmpEqiFfzeR22HOQCNGHa1xSS7BgYmSsBBMO52GWfF14oWp/RdPFlHjtLBX3p+d5KgQzBXPW2KHLrXakOqKO89LYUzYZGZYY+MC4obVuP2WKFvLyjUr2sIZaRPwB3e4FsVeYA33iQs5PNt/dfq2z7cI6YHkKneQZ55wsV6gjUA0cPlW3s+elOst8FbND8FG0jcaOrvRGhHnxOl9qEDRMw8ZZFgJAJxgmaxHIRfviXM8pNvSh6E8EN/eja7CILLdxyFPpgw14tuRq89s5Ik3ndshMmSFRnh5evbmM9zMlcSyWYOvXJm0poYLM4rBJOQOF1HvmLix4/qoan2XnDGMimv44fnOYJplUbgUhQ4mjdBdVO4gvRf+BGGYubZNJbk9Q4R4ZzT13eccq4B2JZoIam8KcDDM8vkmgh4BjB9m5EHin5Vb6P7z5/CjBX+fogxeNzpD+o8F7V/0yiAhz3Z24IfObZHEGWUzDPIVRRkxWyXsUzdr48x28CW4okJrSFlZ77xkgsgPnrveuAbIzJiZuHijudA3Ve2WkwyIcO8hxJ5k9cT+xOqX+HRctLmUrAzjClSWflPj15kSXuYdNKLPEWm8sdPEhw4e3AwobnDh2Qx9mTCHVfI+NeD6fzWmeHuQNDUWU6K2VQsat2BwC01pQTmu2ev9t7/jSGSn8OM8jOKY7Rjx1yg1yr0R9suEEV7FCb9Dxs1c4+QYebszDB+m/ifvzBt518eAemzlaBO5jbJ9n0n6CpGoEcvdApGDKQHJzKLBjeBdCUU4saI4kO1k+mkdUy/S9XTss5Ym5hut4o+iHAJaKAPbVyNP2kZB0DGYbcO9ceINaRVF8PDBpb3JZXrCIwozCdoBlEPuLPuueoWPT5QaKr0UjpDbv78OPYLI9a6Q+xTsITVqiVpn41SBFaKHrPdnx3S3HNApHMVclzBD3xVSLFjqL5XCHqaJ5fA6f1Kd0vMAF+CDaZD104mdZAdRfKOUeDRNmNrNV2+ZsWLDzm3l6B4Mcxh67vG7Kq6W+ua/2m2zpjVYaRDbTxoriJyvK6xtrtDKY49CyYIGLJOzeJlLKpoNChTpKetsliwnpkA0lyRPsMGEHEO2h37i+irFAOd2NlnN/AWJNsJfGBgdea7lh+Ydk6938RWba2L2kRIYATLDDA6LA14KoYYegvZDunUaHl3LwiEeH73y86OTo4MLHLJn8OPl2SkGfdBHjpEj4rJKNe074MFPfAdH+Iymne9T9iOoAQpa0iKB+cAmf8SL56YV4Qpe49NKRJr1LsIJLqhCc86YEcbYuwakyuXKuGNiX3pT1vRM0VNGqO0y2IHRstCaiVTnMWCtWzY1M0qt0Ww0uVBHgq4s3dYQhpEB6Bx39y3iTl6fXEJN4sgzNc+O3pxeHFn7h4dnpXrbpIkqwsRNKQ43B08OzUU+1D2VbDKLYwGiwJUX9q198ecFF1UCwaOU+qPQurKTEJYH3ydb1Swnd62DVh36CbQJFlxKURBvMWmMg2EdHp/xWqmD5MSY2sVcJfEZUTj0Rzwa6SUjI+U1Ie0TAoiKGaoQGY/pFrwUoCb4ei+IY8DS9uszLtYSPYtKuay3zF0GV+qa+EFeWGYjZzhZSoF5Dxet/VcwufyAtgywG1no+ldspDBvAheIv9cLzkxYaAsJFZ7OngrTUgj0D29wFkXyGJroNiaugsOHGAJLHP1J3LVOTD1SOaDMJtIDif4WkAVVb1q6pS4qBq90ixsl0r5NDFR5JPJEILJmz8uDSJ/NxDRzTKsTbU9AfCFQmx/kuaVjztLddY/APjeP4tbulV3CH26yKUP97vW789dHJycWtIXJHny3JXJHyvBZf+/fMzTbv7mYykx8WqSKxPYNORwfJRe0Izhrzie/H9Mq8ldn8ruZQ5QnsJYyZaUXxHyyuMJ2S94rOpUzgVesyk9Q2FiekCVTT/D/PSpbjSVVJ1IbVTdppgY97jP8ZVP+DMbWOj0vcAPX4fSSTjnHtzqbvFbMnIRcy2eSPu3eV0FtHMCiW9XL/GSU0l4vNwSi2svhbPV6CpQ8iwYW0iPDYJqOyfGiHqj1kOflFl9LCU66VqSopJmdTREMOFaqbEpJW3NxlVhrruAEWecXZ+Y96X2gSqB/W3XwAgC7c+2W1B55xYsV8fw8Q4DlBj6RAp548uy2+BfmCmdqfcgz7yQKSxMAQONZHF2Zq+2mvK9e2qzBVbm9jry6CBb1JSpk3HxGf1amNhdXadg00DzknCqp8GaFIMMLJcZHJx691S6HOarE0X8X+xA43rFrogOxuwVaDJwTlkyi1xE8ltUMc3Foszafo2PLJXPcXSbiP5vzdHz67AuzCTqR5k2jnMexh++BMTgKUIBS5lz+KsjWiUJv9e531UqutpBuZaVXiCOz6sLDpv6tGl5s8tIa2n4w5XItYV/tR4kSR2O9tPA1dOLgiR4o0MQQOvSaDNAJkTmqMQUUuGJHKuYrRzIURgGsSHlH7JhKXMgHqyszI95EOo6uLPKcENIps5n+HbBwc52e+COkxV7un5wf5XqGNBAqEz/Wg0gqEIGO7mXptThT3EpjJgV0QyVkHrl+9lqoj1woK4QWl9eFL+KQ8UV0yJ66bhQ+FjhGFoixRSAn3zpVUaPgjnIt2gnSYbuee4T37CIw80jPw0tXSBLdUMxjOVJY3vsjtDq8XGzWokTGsS3GMU8CKWI4lcfOfOPKpGEk9+Iq3ixDlJEXItfhnYHtiybnxVQT6c0wv5rVSDBxCLI0Tbzci+cXLAza+lwCiE58t6bpcy2qGVr56+98uT92J8tXo5L0+KaSRIm/oLBumbWdeuZngcebO5paLkDVd64YPlbKtrli8j4N4sZRCSivbP792Boi0rgvGsktGdsq5Vnk9TjkKdF253JDKcG3SBPSiTLvkSKI43xMY5BOd71Adz96hR/VUjZoXs8W/kxBAxTpZ1xd+Qh7aKgVMBcDNg0C8jp5tXAWucaLkwgk4nivSpqTmHBEoH+lSAqIw2IH3vU0fUOqhovlriHVXRNmmD5QAc4Zx72T/QVzuApuPs7dXUWw75gVvSuH2CtfaNfbwHYu76ZJUNSB/+/yrTx3KaXADu/KwPfOBl2VZHf57p27idu640ycKzu4lI8coV1jf0knJp086Y8ibjSqbG0fxejrLUV3qLhfjYM7n+zER+hSKOgZL7CsERTo4z01knukEw3f7C7KGxNx+yvyZSsK/t1QW0G4NtG7XUo5jJilchRHcfD+7OT03QUZ25fHRyeH53KDIpiDqR+4bOGwFiaoc4sU+ER5nNxgcB5kGZ1nivD/6G46BcMeEdbTifDHEPn9Q3/fuK+RUrB9d5o7nC21I6hsiUQoyslfCMpkhLvi8LFPnSS4HXC9k7zgu3kihp843LHU/EDxuHS9fI0fTzGBdoumy8L9d1bgTzCjECSeVeGjxoYCCEi6hD4lYRPFM7ZDfCh+5qXcVrH2N/aIEqyPebcDBgqQDuJChtj92aW+Npug35/L+cxF85t10RPix+XcHWiCUw4BqfgiJzUjnEnsiZXvitCL0EMpHrPBrML10Uv48eIF/nipCKNB5N4ofdbmYKUx/4KUP5vrhUW2mJXLNPRBAEGX0reJl4y8OSukVnn1nZmvnzdwFMnAfR7saZurTxgxM3MJLg69XPIJcIJSzlyvu13Z+GeuRDj7xL9iQeYlTn/PpZ5CFkipbovBXckiN1JpDZSbzC131BZUEnL03KMgukJctqf2zXA8wh561kRhGYom6EIGPFGwspSmTVCAi6pthjC9HJqMCuNcrJwUDAXFTvditXQ6ap9habcjZ0ul65s2udcreYKUTqECtJRmLXPiYRBF2OxOZsOsZQxvKDjQ4hhEJHsUeLWyturz7oyBHUq3VhsbEoDh+m1RDGYNgOr6lWHgIwBE8d2O3H1xsn/w+/u3x39i/O7s6A++S0oF6dS5FfJh7sJ92lRASe07KnAnesKFU/KVEMS8tmW3NV6hTVw6xQ56uA+b8jrLVqEKw6SdEbo1m5gcsom8bKBSuCnJp8R66K0iuk8OFD+NkCeml+M2VsrC4iy3vWk4Buy02rieUTQkb1y3CFNZ/b3ZzQKL93jXsFxVZLktQ9R1KetvJgHw6+OcF+XmyFijCpqfs9kLKhsoR2VftqehLCxuDMW3B++5yJo/1FKv8VOe+nGF7s5ZMn4SZQf/hLSyeoopbv6QifxcO1EIpcekKUf0hOlgTUIW+XHYg5Od8+ll7S7DRisPVOEOezqvTs8OMWSu8853DpmgVnCKuOb/Ne75iqhSJ3kzBYI+hsqgk2eM7EKrNGedCzecojvY4n28JoXi76r1+dI8ocktEi1hLPBv0dz0adcYAzeTKm4sfuW17TKyn1c3D2yHu0SbgwyFtAnifV7mW02Jbm1ufvJTP4uSi4S2nm1u8v2WVN35dXPzfHp0HW9u/spmhEM8uuxuQt8kHzSYnBsuQykLBp/3oPaEV4Z5uUYJGvILi9WEM6aPczW42a4ocKHNcRnyYFyNI3viywhyWRJsfXHixtyY5dkCGz8utBt439p/9+7o7aH0xqCQFJ+m4PpJsYstj/UR6pNrvBkOQ3+qV6i3uB1NMY5zmzIe5+EZFIlaRPAsoNBVrGWrXqfdSXZ6ycmrV97A3P27zw1SGLsteSLVCAw9+SEJ5A8oAurts+iqn9rwxs/uJ2/XNRqMzAx06EY+GJHESsfTDBPurNLBIDRUc56GkGGfzRJFf88T2ePfmKnxQKEQrfbl4Q8SbSrizXknHdl9ge/4yeaQ7h5HoT4/sjNfPn+jG+plocoFOMEH+ycnLwB4ylXOqkmLPZeLyNn+c1NFI/4vhgp+yGiRBm2pYOJPpDqf9H9ma7DQvOsM7MKjyBDS4tM0ShaB5Tl/WdYInxYBes31HHCE2A5n4OSn/VJsc3tvN19DeLO6UL5DyBAnPUjOVopij2g/b+DbD1ELiQ/E6OBA4O7UWaSTA6s8U2YGRNPol4ZpXtUs1jOz5PIC4CQ9JCdKI4/2m6/VfwSTD5P7hJPgvz1a7HA8fUql93YfWB7e42Hlt/Z2H9OPx/VaDSSlBHSrm6fv01SUgeslvh1QMJJGdefVu4Pn30DOBuUQUH5G3fU/ob5DQPcOFue5Y4cK0xl8ZhvM6avjl91erVYrDnIxKDavUf7pQrKodHLQYkhVQstX5vqugDSsCaAsfTB4pxpOEKULWCjWOSEdmLZqkRm3rHygmxJgPCCp/48omhzIzunZVrh8S+jDUtCSq/4RHwgFZFAaAO4w2xkksum5up2NoBze3KkPZJAVKF5w0oeM5d5ucbxOdUEu86EaEy+zKbtiWZFjhlY9YUFxUXm0RA7HKpxD5v3cwebzAj8fnB3tXxwtXey/ODlaOn659Pb0Yunoz+Pzi/MlOwFVG8hb4+Lv8KFZOuVRP9Z8qSMgVXd4yHm/Xm82mc7CLHNrCFrMS1TuOW7T4IOnKLcAN7qXKjlqRyOe4WQBPMUMTysKPUsOf5MmuAFd+FVzRV6SbU2fXIs44C1A5i/4Z3mD0jzyHBlDZ+eqnTsjPzYQ6bPaj7bB3VLp71+H8fgetcqPen44J++wHTOqpxSH8hGdJydvLAyC8d22LK1haLlRENzw2EsWCk9C6dwVg7IVNE4x/VkkAwGDnLQu/OaZM02LC9wTJiR7P6kn39uLnrDDeSiGWqyGw0qNFBjSKGXMKyZ9Ns8ki/L+PcVENSmDmkEVccbVIsT38gNUMJF5zN/o2U+ItxzaQerluNZEfaKyGX7DsFSdDopKn0nKsGGohJ5ZdrN4s43feNdEX61lrmhItlLlPM/HnhpIGR7oe3NM9fvbaeUZDN/JC37Hk2mm+PF88h+ZnOeV0N3/69A0dpL7T+bvJ4weAQnZwGJQngrGPfpFYJ+TZLblzE6DMk9g2KajkSMndxmUDqI1FkTH5onpPid2zJaLEnfB1Xlae60wc01F889V40dQXubHOXaT6zJEW5g/U84B/VfxMd9T/79ZgztHxlBr/IxzqR5DZPHDmwKAZpms0iGU8/OEuVn9yqmK3wjl8rP4wJIFtNk8MZtvyZiPGMnZ3WvlE7PX50LHqgF+clvhjYXhrx+mq77lq8/57qyVKENHa5KHgXmDZLm2q1C0OAVxFv3JOU5+ak1jTAb38mzWChc3U+2+pvaqtCD3r6uWXK0+xqPZ0nUvdJIbPAhvnY/gQvq0Bh/LWXVcV1ln2ipjebLXWwUKVchqE8MCm2AmXcW8Gy11kmAFShI7gYUtxTSr9HKDN8E2upK8mBS777+O42owfa1G48subugoeVYLEmChgOxOlPZFKfE22xYfG0K7SlR8mr+m5gdeJrLpWl3GxnBr9cftCqhusSpoLTq/vrjARLcd+4I25ZB0TP/KrrOnTH/3FTlerfZUfZ27Ly+kds19VfS299BocoWWhClLdGySin/zFCYfDy68zewBXukT+sELjHlobPgiN9ZWAbV7/LG4kFiTkzDKqaCzJ7GjB1TH5247YzuBxvpXfuhGV+mmpre0YsY5GbY/s4dqfquHyGdHgBXu9MfTIynBxFLeNbWISanBmccnbvK88xZx3LHMrai19crLLsZ+ehyruuzh2mowCTWSR4InpXPdPDxTZHmnZo1SBU9lE+ioOIsZhwrZC4SVckjbbOmBH44eWvbGHkcMjtl+cZoSpiTS+dxiM/KN2LxcXeEZymWK1MZSGW5SndsW06G865uO6JfCxMa01TJH3JS2hJHa/RCc0TEdR3IeOZdpi2+rbYIld/dF4rsj7yjF7QR+Ota5IMl/xS9+ZlnRYDhNHWT9EplTLtySlJzZfTLxFeuTj7TK/vBszLg58eWAB4PSiyjX8MOL44uz4z/ZDfrwB8Cid7R1h79H6UE0mXi4TZYvIP0S2ObHnfrYYHzWVge5SYQaiv1u305vbOU/UPpPR51AvIfeOhp2ptOW+v0ltaGltJhK1H85u7rQU5Qi1NG3Kv9KwczOH1mwSXR9U/X08qcR38CpiNQq5RN1Gt/5j03kh6CppARuUxOqiY7kV6AAQDf88B2A4OpYe8q55Cq6ZOkpEVii84H4CE08jRVTmfp4yioXVycjmB+/5Ae9LqVeMNzaenP6Atm0V2f7h0fWvvD1lG2kaVoxeo/yZ35Tyvi3YkhLu6GWT39f3ibD6Rf/RgmnUPPTCYTR8W3/r12f1a/bbn4XdfCyMpIPqdMR4qvyD2xMokG+ESiXURpCamCHz73hBrq5hZzhJ5bZHtfSaRqDivBchtidUvL+nFFn07aMsGiZ0UB65ef/gkOVvKA1w9lXy1V0bfLukaJ8f1lt7zMoGQtZ7PJSMlfz2ROI3FUHxMPwYV2Hj1Of0iHOcvwOrJWI94EZXUV6S5LgMu6F55OljK7aSClp63sLEdW95A40pGS5eAm1aW1v5mTlFZikYQmi01lGhx7Pl6JCuuqMZdz/k2ZgqekYYt7aw19kq21cuGW8obtVsQQoWuiL4Q47wT+Uj4Tb6ysbquvQMdp1k9aXzZm4E1frSpdmq6WxDyq4VGtKR4pxJdqA1ilSOJjIqOMmtzpJzG/gt/+mdCCngi+rpnj30pf/AQ==")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1551220944*/base64_decode("7X0Jd9tGkvBfsRXZ0cX7lkwdkeVEM7alleTJ7hgOPpAERcQkgQCgJdny99u3rm40DuqwM/My7+1MohDoE93VdVe1s92udra/eNvVnWi7Vd9emTne1Io2rDVr1V77+eji9vTk/OL2/OjsH0dnt4cnJ38/Pro9O/qvd0fw9tXx66Pzdev9yo63XYP2teb2yk8nF2+PLqxo8/Tg7dFrLKljSXd7pd+Hft//uPKh2bbK9XrPKmNpI1vaq0Fps8GlTZzV9srfLtxwhs8tfj6Zu3EHn9vw3NtesVYDJ4rsRYDvOlzn+tAdfcbnLo5Qa2+veGP+sGhjvJgPY8+f2+61F8WReo3Df6lu1b5ag7VxHECpO7yNbqLYnd1GE3c65Tc4VjwJF7eBH7jz2yD0hzb+Wk/aQ4fr9Acn0IMJ1Ds4y5OTk/LmHn7pIpyO3KE/cmnsPVpB3IIGLEUUh64zsyN/+NGN7eHUc+exOcV4GGxXKtSEVh0+NhjOY54dVaQyXPdGDVYWXjlh6NzYMyfg4eAvDBK6n+AH1cVdaDS2V0bu2Ju75mAvj14dHrx+/dPB4d/fHBzThtZwVxp1mqjthW4wdYau7hgbvahMXGe0S5Vxy+rQ9dAPbsyOJ3GsPwO3sdarAvT5n1zYxqnvjNyRPfamSb8AjwRv1ntzp7DK3Jm5qaX/kK4TzwK7oE60sfVd3ebL6VsQ/Oqwi+5w4qcW5e3JExwJf1LFruwdvqhYZWuj4uoyBJlOVXWyCQvtBdHUASDUwPrI81mvynCVRRRWooE3r+AOjKisJsP1qd+fX5/8dPA6WZEHjoNV9TLU6zKcteos4omNZwYK+1SG0Fbv6a/Ti3jp+yP9QDUR0uoAae4nZ6o+/BIOhR/g8aUqCF9dmPuvP53bL4/PsFY5tfvuLKik9qlMX+kABvjkvhIQSzWxygAy1DkCZrexFC5T8IPN3zulzwelf1ZLPfsDfRcCDZ1ZAwYZ9qh/BJZuTbAuolxcZW5BM3GxIJnXB4HYTK1oMfjdHcZmPeodIazTSeF0V35vmd/bt/beXbwqda29n6w9YxUGTuS2m7Y7J0QFrcehT2i4jvDZJsT7UCCE4QmezAXiQ0XYqkHg2VOnYbRZsbAqFG+4VF4T5Pi3MzcK/Hnkbm9HbvyTP9JIJQjdS1uwETVBEGwD8Ozv4YbZwQKQqT+PAZtGjyBv1BVCbC/ZJ0KfyYmEzmKfEP5WQZHsztLymRtFziVPGeG93cB1zS0UA9uDXvOKKsTrRfZV6MXOYOr2jd9Upy2rul8A4NzzInJDWj45Eg3Cb0BNgXTGUGd9O/eDqhF2g9FLu978k//R1XSpQbCD5HCw5s2H08XIvZX/2v586N6G7h8LoCrqv/RyPYVJK5+csALzIeLRJMjpMPLKlyLctBBS+XMidz7SmF/tjHqWndDPSMTcMKJ+6oIJvpE1sNZwatOroDTyr+a4zID4DBLYJD6oWmOiqmgqNSoLYlVH1nz+1so0JJFx2MmKM5oBOYCzMfYuF6GDqNUqB5OgMvUvPf5JDRCiOjhFd8rLlmpieyMYZTP9LvbiqZt/Deh8wZNACGwB+l4EIyd2s30i7XPjO5ojNDY6xpSmzvxyAZsYyXQQ6fL4I27RFUZ3aJWBxl/GE2t952voxotwjptu0YLR352vwDGuPQV6c+j7Hz2X4beJ8NtsETu5VohYvPnIvQaKF08YjNTQraosOPNpm18IWpESRxP8+VVoYQnw7oQa1GRxXnjjEL4DVyMc9hX3FAHsjPxhZJWBcF7CiS0P/Vll7IeziGCqVRfquUU8mbUH+2hZc/rAsrVKVRDsOlBFSqPNx59Kdewm/szlcRXVvg4XMze0owC42ak3/wgzja9jqtIShvPQn429cAYDX4TOPHKGsuuncJCu/HC0TbXbQsiEjXXDSyJH7rU6u1TAJ+DKHUSxQ8SQvtu5wsdIPyM/4IdOeEM9I/z06t95rGc30R/T0WKG61eawJ+pP3SmEz9CyC0taKCusIVv/HjihtgK+KHNN443cvF738L28rcieDUAYWEffBL1ARfgXAXhAQ7yCLZhSKvZVoA1nMz8kbUGJQj21ppNvIltW+u4SNVWrcbYuY2A1W1952cTlzCEyeBXnqTxWbsuPB6QvfWt019ObSCw58cnb7dmo5aiLwSCbZI9mkjz/li4IZDzzS05CMhuPKtXf/dBtIsEEbebgu6tATGFa4LgZNiWiJPZUovknDYJGtVmEYHtFxLX3LutJWRYBvqSKaNROyKJPXWBRZGqv1lrC4D3sWuHzhUs0p6sBsJJg/hm5L7skQ8sx5ymx5yv8Zbq91gCjtxr/ock4KqQfmtzMUcQ2hT0uFndwv9TnZpgTsBcAGjWWvW6Xuu4W4EcvK3qdcPZwmVHUKIWddmoy9BfBPZd7ag67msLNwpWH1bokXhFdqyD2w376Qycj37l4ITe4SY3u4yBma4FfiQEnkhDQtGd6GNaGO8wCMBhWcwRJykmnlnAtIT38uTw3Zujtxf22cnJhcFd5wSGCny8G0eVoTOcuBWSOFCwOHfj2JtfEtx2Okq6d+MLb+b6i1ijzoKjTk0QFpoNYgn4A1e9mUHbXzCzrj/WszZr1I4UDlXizoWXZWFh6kxpa7oKPqpapvq8ACZ/Biw0iGk0eFepFi4/e/PxFGnzGv6fyhASmog1Vz+6NwKcMBjw04ZU8oexYjvUrCGKEPgeIL2y8kgnL/yXfqi3qEtccBM5VyT+skHMnNMGAQq5a9t+ubg4tX8Bvp46a8mg+8MJ4EXVjiUoaUX1SNSDQStEvonpsfZYzuzD0igK//yT5171nTD2hlP3uTfqK3IaILpPvt4bGZ9PA5Beik427j2CEC9bDGTsi2xgtEES6m/0CGvL73/H99RHl0/768Y/J0Ov1yDpvUsMCS9r7E/9K5e/ErhbeGOw8TawRXNFMRkL9BASmk1NORi5WdEzq7xvlaxNZOcr1tWHzT3VrFltUsPaYxt2Wi1qqGBnf0GHc43KOh34z3P49/9TR0gfAjecAQCImN9rCMgqLcMt4oiEd6I6RBrgZO8kZfCr5FEhIY2a1gJmVYDqLLImDZioj9SqLdKOEi5QfhARuoRLWRpTtY5SrqDcAf+WYLk/uSGVdc0yq3x8eFQCrEyIutdTmhDkCDUnlXyWPhO1alVpEctWuZL5A1uwmLoRV6wJaxX7i+FEHXDNEsBvxRVwddoPmMJ+qj5wrYtQ9ByMXWJvln7g5kp/W7I2SsK947LAE5c3BU6Qb1Cdv/kfnICByeA/u/Bv7IRa9VKrkrRBpBq48yf9JzDqxItKu/ZoUNplceGE5be1pCweTLfkaSv11obTxP22RdMw8ly95HP/CTIyXIEOKgycOkChqB0SbDsf+xqDsKRoR95nWRba9GpCo56KNhfhJ/aVMErvdI/wRU4iqiUYUt5rBUI1mUOgfwJPG/PQPS00zANENJvxTeD24WNmHj4Rgey/C1gG3ajgwr8gqYH1taSGbsHMgcqTrMyzUMgaZ0w6yA34025ZTKujDQCkpkymzv3UhP7vu2Hok+QJUwRyyEeePggPaqKVf8r4Xg/G3RDXgarQKS0+YkRRrRKLKPoxrkssB5xx+mI6rvTVAmL85fjAX/8E4VuBH3fQFKaI91ODx2sh0Ns0L2QbkjFbwtwZk3ox2OURXkTR7vliOASqypXbQtHxLNJMROUS8jQ2hZ6Yb7khaV1glNIx6W9JwKgMHEJGc65CEkYzxddo/l+jEdIst9qGJstaBeFJlJR+op5Ml6CmhMvYtEA6F8RGCN6KTGe4jSJd6DrBC1O1PANOlPm+PhBmlKZph2dTE13TfEGSCyyeF/OCkxq62Sb5tmDQJTo1XipSUwOeiGefnOhmfhnyWyIydXw9cYLB56Ebjsdc0pJpAAoM2037jzAY/CGN2mIdI1wzHoMYoLeWdMAwzPjStd3BZa3Bb0l3C+R1MYTRB/yuZ/Qyno4vw8+6F9af1rks9OY3SUmN+3djZzqee58v+W1d6sPehcHMH84XqqQhn+GO/KE7spttN3J4AqSeVBOIkVd0kmFaIpfhm0YtxhPPUjcXtw1rhw/zAPYqKezc8WHdpR/WU5zEQ7eVwYUUhig+BE4IshQJnTYqZQU1WatHb//xRY4ywOLZ/9jnF2fHb3/m1jV13g2TxGyA7CEQ/JiV5dAVV67LmdRgr0RqE8Wx7g/WhhjXg8PDo9ML++D8iAubcvIVwwLtDoFUHcQx4GKuooTefRbhNdpS/beFdyIUhYWTeMaHn/QmXKkjiIH1VYSGntWiYegFiJIJo7L+AfnVyu8OgCUX0stnDLakXUPVjyhkZCLPajiiqtMTAjxYjJyPxCzgiaZTSxVIT4ba9m/VThhaqQwYpHmqlhyNnw9+Pnj9ojIQg2VdJDXGMoTQ+VN34UQsZshDlxORjds0hHAQU/GwJkr9CsjTRn7Knnozj8Udbx6T9kKQ8OUnbqGUZsq0uAry2hVIuyB9TP1LJYRcsWq0RlozPB8AmkqDgBqaqTewyghqh/DeZZjCkRahx+06MrGEMudNTsT2A9vOLbrCJTOW1dMTkWnH2pOV7YmMRSosS4lAtCl7qX3qq41iWx1LllK1cENZwqyRJoz4LjI3pw10liEj5jr5VuPxqciZNdKp1fAYL7WlPHoid8yCp8kyo1Bl0rmhXX40j2zUFYXu0A+VcKY1SQJ/Wu92hzMEdDK7DpmGkeINcdk8mvr+x0VgleEY4vEl3PDmv7lWS9D13L1CTh9RlWxNWyQBFu9s4WoVALzQqMZUcXNLBMgmsIBj4GdJDTIOlORwfLqdcMKISF4eXDDibCuNayKh2mggJm5IRNkq1+xJ/4eA+N54yK1aZfaEeHP85ijxu0DEN/PCIbUiJRvycqwPWlfQyvaDOcC8RjbqzxduiIBCBrDVy8+BZnwGl5+PcAPwAU/R/uVnkpnQuDgLcMnUN4eDNBojxVynlewksp3RDDCnMivHvvUNNq8aqfDatGXZ88+K+rROTLvwIOw5gKZJ56/pNanyEK+SKtPQKkUbYmgWjxiDNHaU1K42kWCntAsjnDrxRERaLRgphERKPrajZiceB/WMJg9bOyTppPRN+mCT5g7EqpxUcMjorXQB8I9Q6M1gISu/B8zcaQEnhFYaCSxFYOsGX5vwKqQCJCceFNOA0RnXDa2+2rNxjSsTem0kym8ra28vZoyWqLTX9bQU/ia9YaNjUgYvsoehczV1w5pMPA3spEZEZstaRbJg15BK0a+6/tXQv5r6V4tb10UbThgDwcqwsxWJN6RixCXY/2bLBq7zAqVvAxYTYCDdZI+0eNpNZpmw8/5BdUab6APBwvYaPqGMJB5CpLtsmbzfJgvTzWoT4V7WmKC9+x3WHAHMwBUVCOkq0SHou3u8iSeswKuR7rLT0MCTSI1abXy3xGgI2H4if3eVvSx0p6hKjn1nEOEPtXUm6zAMmNlltScsrFisypt7+K8ofZ0+bMNzIELmdJ5HfW5aEyWjsSdXkX90zaV10UCMfTj2QzWJ2Eey6kTyoD/JEMJjnztgP4D69yMbRUL586zy7wHXXM8L0D0l0wL/1ge2bQr7KiWtjDKJBQE6jytIq73P8ATLhQ+k1FhhxmeFMQbpT2s1skUIpYlgNz5oqlfEEimXk7vYsiXOeSl+qKc07unJk5CZaH4SVYwxrIWKMe5EObK8BJwaogINWWcuInzbIQH0Sw7XoipfY3zTTLO8aoHtsE56X7JQ5/zy7uUfi9D9+4J37LFHiuMWihd36usU766IvWH0rVdZq1DN2Vf7aWjEp538RPpjxfGkXpPZPkyA1yComQ9heK6TUhoZorQU+uJpqWTKFYkZCY2PbhTbSirBQRzBx7RpI9kMpQCBE/8Ln89I3JrqpK9uK69GlgFRq/pk5gIOZL0eimcyA6AvGhpni2nsBQBdpIYtIWfMXSp1YTH5K+KabG7YEcZtGVJ8nOdoV/jjHDuJk5ft1OAtavQ666FrJrPwdJnRBUgLfR5aTu2RRwJHvaYcu16QExEyQP9wzuAfXpya8ghExbBo2YG9/WOKy2pyo/DKi11uUxfVA8uXOQ6nThpkFHLENTW7xKtcqylY0fohDX8/wGK8qIjkj1j3h0qmArdvZUQvGMm29Saje4faaK7fFosEsHoac46RV1jLYBfh+wrwCGmQG8qVdk0L50IPEtrKtbtimDp8d/b65PTChv8Ye47ChTrz7KuM20Q+31BDqT7g55U3H/lXVjn2A1MBMgndcV+ABxtUkhaG63id1MydPDaRNVDYooCrJkpurAv+vOI+Ff3eR5t9mBjhuZTc/Lp5/PWIMyP9jfxEN4H0mp0eeJSGLJlAWWawndlHZam+Q1zIuZ5x100tXKL3TEJnHzl77enLWu0eS23XiQUdsQlXaIuBBgYpkDZSx6vOotT2Clr6os3S5+Ehv+8K2574uydujTIj6z16EZ0fvX5lmRCPJ1TEwMQbAMtVbR5AifjLMNC46MyQUr1JnzZchDZAr+2N1JKy9GMIjLDA3KomQouGcu1cp/cbu9MrSLp41Othv240JDJEFnzAW/pBwygp6NF5C70EVNcbd1isTJonv9OkOLdPWtGfoF7v0/wzl7VEti4cPjv2fQOR6AJEgvAe+nglamn9LaGvmTISg/E3uazCDoZO7DO5ICMCeqcKffo2uI992xmNQjHY1dn6ANAP7HZg80eS4VeRAjJCICpPJG7SZu6ai/67782FSyDjAwLHwEXX2mhz5o+20ftx4qB/ZLQ5RkeYTWQUeAba3qA6/K2AgYs2mPEhe0O7Veg/Xi5sd3d3DcXOPdrMF208f65ZrEyLu/hWbqtpN09DiSdW+erqqlLZDmI5OU0Fi8/ajWed+rN271mn+qzTfFY/etbhN41njZfP6p1n7S6+x3+qzxoHz+qv8B+o0371rF3jzshMAqjzKiix30/EAiE7JxwhV8wVKWqjl3HVNlxQATXHbngOSC5xQ+V3R/MRcx4Zp1Vro6JriudbnWwpqG0p4P5Mx87VmRMPZT16govZl+Mux486WVnQsGTdDvzYuo0CD0/w7RWMVPG4Cmkq6wU+6S8qA390s8tzThPebLEclJbyHiRLz0j62UGd6o7UC4FTeF8VaYQsKr3q8pCLpTqrghiL5VbeOjsrV0UteddgWU3inRC8ZBL/zj7484h8txqZz3vETFKWjn9FA56nspC/9gb/PZvWj6OfFpeXN1wmFvKZ4wD7u3nD/D8ZnRrCqj8pdsg1ZVMyPjET/WCiQJQmihZz1s7U28rK/v+GE3f4MVqgGoxLamKDvZp46EW1GS0CNxy76mSSbQY1TuEMTiQZMZCXMqhyxaQYwCFMvCkH55GhBu14+uRgBSs5PuIWrtYdjhG3U84sCpkCLrPFPXbTWQClC+BMu3M2UXGTllCnlIJXRQwJ5AAOPlWsCxt1UBumefElpIc+ETArEW5u2xFbsQ6+oDoYvYNonuuQHFJl6rdjrVpXX2pbzdbXHU0cyHhTwwifIZocyM8RmTw7zUMUMdEGDpZaZQDJVrX61ZRoAR26809Lq+iTurSQOR6OZySjUa22xAE92hhOQlYCK8pM+uDyn/KaJ1AT4662t+mQkgr6oPN5sI9P+0rnQdYl9Afb3xPdlT66shmm1kkpslRZgmg7CoxVP6lKd7RjXlTcAUjRnCOItzlh6BaDPm7JakSFt9HNDM1RKecAQQ/pg/eIsMB6hz0v2kXb+UVWHr+t/Bcu5g9pi1QcO5dRxVptw79N+LfDpR1hKwrlsvIkdrSLW107rZu6DVJVLKHCX4RBYK/1monmDBxHVbqMfhsZ18xCe9Yo/UvpLosOnRk4ekeX6F4dChtPZq12W0UkjadekAguOkCJtIiXyVIdZDQS/9RYjAxdYrDMuLTnghCsaCMdglDJbAEZwRokCXlz1HHYkmhA29o5nIwrN8XCyuoQW3G+OOeDc5jLhf3rwdnb47c/y8Sr3Iz5iu2VN4so3h/vwy6fo2GIC9uyOoYh8iE+Wst04GSOKnJVKHbarneVwjLHtyYrlSKZ3KpniOH7e2kLtaRLSEzTdbIhIfm61NPAmI/ojTPX20rGonq3YCKAbJ35KExqkqfYssikKOcYeSdHtRzUE3Jndmgi9bvsCXcfIzkKJOekFoqlyLxSjWC4n+/vCxxZI1D/zyvj6SDAo195ElUz3TLVFiygPe33xw66HN+CaJSpee7GJQ4J5brcL56IHgYpUjStFudSmorM61rmuZ55bmSem5UEYEyHyiw3qi1fpgsX+8J7sTsr7U48cvTZZT34aFOrw78Y+0anqJOR2CSANMfiL8IpnymZXk8xOqQ6mHtIr7kHYNP8K1JyEzXXQ5PQX7vHQbjIEpI1AuEEGlWmFXXtgY9eQ6oTdLxXpqYFz3+iTDMftp66syC+McrQEGZoNsSVOF8YbaDKq8u2MrHON8ishtoC0QBrbIFmnm3yKQK84M132NagcdKDhZQdHqYu5DM7zOepN9jmKo0lVXS0fIMMXKxxH/lDWa6/vXKGALs329uw8C+VP+OawgVQsbTrjEbnzFBmBa8GGcZYQTxyx85iSpo+2/nduZYB4nDhyle0RUE8cj8OHR3Z0yCDlkn4SbGkkfIqV1Km2r5h3uEkQ2SMqlUbqRNRTOr7gu3lxBdxAhkVn3Z56RMIE9qgUdmC1UqT9aU0fYkguFya+hPqbfE8a7JDYzNKB5sNnJE9Rac0FbjdqOl4ob2Cs7i/l7GY7e/pTEfcvCEuLSADpGby1fR7apCFrV1N9jsKQm8ejxm6nvkKBalAsUi5hlG4MRSUmoIHyNbWKlCJPsh0pjpR7PFV5J+7w1MH2CdaJi7t3Cn7N8iY1u4YPqnGESHfDFjcDGu4xJol0+kJW4H5LOIhUCJeOnnwtKWyQRa0Zo+lrsEafuNtaodu+Qzdmjxw6sFGsXrgDD/e6o3ENvDPreaQbmV3bs0w0ltmKG+J9fHjWuMWzuwtMwlXzvTjrckvsFj2f3P8c+bIW18Txp7OfZGvgDcXT1ATU5IFFP2p1kiNALyhdQVi+W/WplWyNip4JBQuWf/S3PrKjZRsz6yzSV8j8WBXnm4M4t0qt2uKvikJZXTnl97crSBxrIwGnPZDZyBpcLYnVKO5wwVGbxhu3lE41MRzxH60RKEylrFpKpZrpB0yFOrhWB04rT87iNUu0SYVbR6G7hUXc6hn69F6RMVHZ/G0qTpdSz0/zniVlZoadSUFjVGBV+Atk4ok1yusAsT294ahC0Bpa0G+wJupgAhQLxyOROLMB+EbV+2UyPVYw9x9wgkPWxPgNfWXaROt7jCQIJ1GQ0UYol+RnfLUZZ/5JG1Jg2yvjW5KsqV5FJJgPhxsTJVYUJkVrZohxC51vxVmOBVlXbCJVdLxkZ7RYm8OHpqk9JrBEQmQk921gCr2k7yEnE5I7LbrO8hFEz7T1qYGWVy7S90zoJ/wJojt85M7Jl6om+XeOYS2lbFcFCGyrIebIBqtmn1oGx6XiGs7Y9FVOupNfEv1OO9UVbLmZVOlPQrEixXUH0z0xUOSkaGKHocoUUVKomKHvalPDp5bb9+9fs1N07Wg3KaanAunynUMNZ0J/xyjoVJ/NMiw3CC3kpiz7qhoIpbr0jwNNyGxv1mYzEx47KU2RRM4TKSR9fa7i4HPdo4RaLsautimjGrtnA+XRTHJa1oIzAx6j4BKg7Fu3XQGY/uFcrTKefzIwS32F2uwmbtNZDKvtimOh5I1Q9FKfoKIKPxjU6fBIZtDBs0LisJgWrUPD4qu1AQ3r9aTYVVg/RJBXkFQtAcwhAeynPrDfVD6rg7G6rA/dCz+0E4QTD2m7JVP85FVRvWa78EPjFl3Lt2SEw4n3ieBZ5UiJZouwsC6nUVzMoLHLmB8qtHS+RYSv9s5gr6EZeFvrkiHsgNEZwctG9lP/0szi5IoUOVqUpxSzo9rpAQhssrXeq0CL/7vRnZWxmfkz+iwrz1J8jXki5riZ8CqSLad5aB7d5ePBdsSNoyHUhFi4o+xxPTG46g8AaVdNLs6oSCm819OfgWE8PLg4uCng/Ojc66sInaRkY7s6CZC3Exem5QNmCuRTgSdtJ5pUnXGjsxW+Th2Z1yLUsb0MqFQS+Lq7/OzvCdYgwdUrnYAuqbbdzR05s0bf2GV525cCd2ZDzypZuzJso4Cf9qKe5eFJ0cNmN0iSzwex5xZh5QhGOrhpojKY/KAkhmfskctU0amnaLvIFF3Wcy1y6qmV+QE0OoZ2swsyEmQTLEWQ1ugG5I/raeT6TlBYsr7KyOrZCnY6NpR6Yq/F1HcsUUF2R2XbVcxLCylk/wlyvuxMDtF3wAkQ46NNjJeltxVR/RqGORg/SAZJocz7a7K+iDyp+jWzNRpXpI7bRkYCik19Z1PE1VnEu3X4Gx0GpkSLzTyPpFH782Ugx1GXgRgc7M99+cuuXGkXCXv0GO+qEBX5DbaSNwo+mlJKncq9vaxwoySF+WLt7N82H5hQs+8bN1RSv2C+eakcebHlgXjFFTVAEK+F728ewFZhIh10Ypuc0MiTI91a2Uy4xX04CJPpA8Wh/sWMOwPtd8KC8idqTyNFE2GqS4PObqGIYU8J0jNkJJRBDgK5JRsFiHuhQ5QghXzYjUpiDHwJStRG7nHVag+d6l8HbTEd3bY3N4+mpMwi9DgbFmrA65LLmj1lK8DoAAMEDt1LnUGZQ6IaWgHB9woiTiiKsRzUBVycECxHL84Y08tPJ0ZyZY7IaMzmssLaOl/BJp/LGnmOKVGl7OtdO5xBftP+Xw168euAoUHUJD2E2vt6V7G9EQ5Zt7BG/vg56O3F9pyeUKZ89e0Y0261dnRm5OLI/vg5cszHqQp7EhBgNmjGCryI6HYZU5zRqMNh5jFyZ4BCp7oCZILjp5drvIN4DLuUaU9yZ+YNet9Gd3Lql+tD+vwo1YloVuOTUfcPwpOzf7eYj5xr+l39Zqrqwgp1FpvbxMqB2Y29K8pIf0HeFUWlTonaGwmLvxlLWiQhFBWLkomtaOWPXUliAmJ2skwxccmbXRu3xzG/v4XvGnsrAJL9ZXZzcFnPBAqe6iwGuT2gQoWI2FZEDkVJ6AkqfoCCowDevnq7OTtxSlAJD39cvCPI/v8/DX30xSJ38MUSzBYGuWluO07sGJPJc95MQiZ40DZw17oFBLsuA6FXF27MK3v5PJLvdcelutE2O8u5v7IbFBr/VlejI/SMPIMSBD88yZgiHaBE8XuADPFDzlqrMHuH5gzYycfSXc3jG0VCC/3gqURU9Qkz49u3ugua2K/OztWGoKtJZoB9ErUIXvWGqzR8Gqk9FhN9ujAKOAAORebLjhJDK+EOrwRT2rk25LTnJOTBzbl1E9ROWrAqfaZeWpWlc8t04aRNx7bC0y1+zjs2iSPD4RiFVmdi2d9FG1pcvwz7GoJBYwnFGXypOQMZ09KIVdoKd5jma9XgsIzu17I+28yhuTSe5Np5E9iLtKdTCBLxup/2yj84W2xhSxN/kQJG/BDCrKzm4g/467BvXfErmWtwuL1V15MaruwuU9e+eHAG43c+YsKvEHRD/bkozvnRl1hjvf3zIzbVpTJCJufxo+VH9XPlPdGk91oanS2CKMjye8rD/mV88Oz49ML++3Bm6MVOrbAFPjTRewWVsNRk6qh78cUEtlPIMRsTuOzQw27j8SBykJAv6ktJ04q9BHT/aMOXddfV/GRSsgmpinx94OK2uHn/SHQKGCZWM/V5Lu3YHklIC0xR8ohJk+ZXme5R+f9AtX7h73j4djeQsGqAH0f5z5dEcBlKgvviXj3IrgfwRE+/PkYfgMYDd0LDpsfXnoltllwSyWnWWXGIPiZgDIynIcQgrzSXi5hUTHCkuUdqPwKBcAQGxCQlhPEL65LVoJ6xu2wMDIj8dBVMMM9kFjWTvKFRenAAm311hebkEMN32dk1OunG2Ydhsyi1CN1SZ43LUlGnZT1DUdi6suIocgzgE124sBwDdR9WD+ooP0fWBkCVaWAUm3V1XtuWxcvIU7FdoiBP9Ypr7VlHQSBJmjkvsEXk0DvmHLbZvzF33zszw8XA5ffMUDVlX+WtYqyBHRfwsm840tchK9NyTGGU9npwfn5rydnL7knlQuhNiwNvDj0rq1yuKgQtowq/Aap7ELu86knqb3MkQ+ABvuh99nNbreykh2/NE1j6sM74tclKnQtl3OpijAzPCDWvzijke1TDjVAISjkr7z76Reu3xOMkMqcaq1NHbY6NRvqno4M6GQAi0GEWxCrUS8ATMOYnYMjZYgr0qXrcbl/dU0bUR5gcyp0j8OICxtmIcZlDQNn7k650MwFSy31dXJNvnqqapQhpRkhezgfc422uGp2e3jbI/6pyY2PDZVLHdhHeN3oYoW6KiSa1vqey6MEsrg7yl3xnZlGycWRDf/UKTkGfE+na4TkhigZVSQberNZE5GL9uEPdIfgNPGSj54rqexTGfpAydMLvB+JXJmXUDXNHSczFtAyRc/IZN7LC9b9NKNUAaatL9ySYfHOcZ53cPBs786PVNq1mTRFdKzTl1YUy31NsnUXM6RKRY1HX2NcMlIv91rAeqlhkobkblUYe68aZiztSdOexgvLmrISSbcg63SxkkNHexoqg6QdgVGtYKj3GmdbBvf5n1eHP5PRWoFrUhFHFSXZw/5N8+RJNpZC2jLbEUthrT/nlkDpTGV4e1xnCUTR3VyPbr/EMLbFfXY0O7Z0cINeFts8U6a2JqcoXn7G7vMOf6hJZJlDzgPcme62gD389Xr203t3O2LRlDIofb9gNRKbdqbwaQ6ZZ2/ByvWXzK69NCI6dWoKtv3e+vcdQ5kAhXIWjE+K38dqSNoqPOLRulVu3lhCrfKqDa7fVFroIvgtlwnz86Eiszke1Kw68/nzggT69+rkuM92ou55rENv0SlRG/dXttDwh3PIB4W4/oXneiea4g9hvNjgsPzv9rn6q/u7Jd9NSLGb55Xz+mkD92XPwf266n+Rupu+gb0g0Kdsf89w5jHzNGTEwq9fTBGQfU4NUyO2tNg8vqxx0XvtVt7k1OYtyfGwv5et/VXnO6YKS4vXt7m7ujZlFdXNzYV0sw+sqWasE0YXTqivXz/iEvSv6AgqV+U1+QLDJg4AAO+BFBja0WQR4zXARmiFsWCPGIlHoBzpHVNHwJHQa9kX69u0w6aaijwoMD/3jnynqL/vWuJ1daFDk5wlOs1sfjB1VV/RsrNpBfPb9PHGLdube6mYUe6XL31RwburAWeoF38v7YIY6E6VR7Z7TXHNRqj7Cob8z6YrCOb8W/1E5Z9kv8wmvK1q8CCHpqZ2d9X3ctElUDTwrnAVySR0nPH+XiqgEj4aTZ9Wxr9PjUXOH2wKx87J1avYl12eJL8WdhxgRCL/5LbcozJU6dhrM+NJ+e6dInso5oRRmstMIx5BXT0g6yPhWDqtc0G/Be/S2lTuuCEiQD4ZsYp04Rsa+LuUSjHDbae7pNhmimePQ2cYm04O6wUON5LRbT2nOzZeqK0j3opSGS094gQEj7Le8ZWUBBBf0lrotDZ8PVFW31dvLVWFR+lopVFKaWo4KGiB4kORDpE8IWp06S5lBe3fG+wswJVjIHYsK7ISsyt3RyCXP/Jcd+S5sgM9UYio9X5ySMqW13wVGtoaMMMcHxw4UXIRcrOXBKoV5gfA4RYjsm2sTpLszcmde/wLoHTu65/QfzbzDOMxGEGGrYmBl8pM6xx5ZWbSIVtrGRPh+dH5OfdD56+b3KijBLrQHbuhG27zoU3dDFrgD3R29Oro7OgsTRrJgYOvOvCSa0qWuQVxWzZ2JFMxt04cSKVO7ISXdNlfnwdriqL7zKVoxbMFXT2J1yRb7wFIAFQATkowO8plRRdYrZqwyKn7NbKyVmtY+v61WOvI/QPZvUIHT1xjxncKyan7VjDeaRagbSmbJxnx7OCG46Oa5C7SkvvwEvMh3S12DtBAKjyCyz4mdQU+jU+kzjIiYKHsvEccRxZtDm6Se7V/vbqyyqe/nP7Nc954VvmQfS2aPeXT+xAdxXL1S4E2gbvvyacZ3873zZfwU0qf3NAbe0lMLZdpYiFZcVv6/lLGr/YnJ0wmI0DFFUlFCQfydLq49OZP6GZ0qPXr6aEfuuc3EdeqC99W2k1MP0l/j5FjChnDFrlOoDq3YACtO5fMKToKdZ2bqsR7bKIyO1iS5KzFfhMgTh6i0RaPxaETou/2C1V3n+u1l9mDHmaoVOhoP2u8VF+tQrQKTEdF4cBGkFgg19G1yO+gtTRrPdbTq/iLtWFMFPPkchc9YWm5MtWsNaoigiWO8DqjsUHnW+QkQBfHPtpGZOlEiXDc6NIIPqbcb034h7zhN5GZHiMmWEqj2+K89KwEs3Mba6eHyzgLfm85T4AMP50kMf76jsGatth/oKuTphdlCfuvd8dHF/bRPw5Uoviabq18PHMZolLpqB7OGbVq+hJ3A5s8qpslgjAUXhyd2YcHr1//dHD4d8sQj3ngjtjjk1BovOkKOKHKi+PxG7qGGRkTTOsMTCsH3peH3LYrJjxJqk350gC7vwsSw3qLs+kjIGTuHh97l3z1OKo+/DneRK5/UZ0ZIA7nOXJMz+NZME3qUb/kjoAeGDL41cQHRtUPb8hnDzNO42WYPAdyOkCl4uxG3xiJ0KAmLDe8UNW6nIl0MNG9mQMMDnork6hTxNpWXZlH4tC7vIQ9JklA2OgXUbArm3PE3sxHZ2cnTEDqSuKGtaekWzbGhmoPhLvY+QKHhSJsTT4L6RCqx5Me+d4XV+qeAku+G2G7h37I2UVcitYzic8e8pqHUtgefRoybopj34/VtcSJvBqwQ/3vxNhwH8rLLIlnK7yX5BGnm/woCgzN1nLHKZnnHdYB8fqbpsiddsjQfkliDcm4JpFwwi042reA2ypIsPfnaMQ1zd57SERIkUGIZ86hi3WlrBEnFhEIzs+PT94CNbJtydGFiTveryAHsGIG5z59UP3Srsf4gV1I2izCin7NupZg7hb5kLRaRgbg9GnD5LWi/YCjkD+R3Alfu9z+Vp+QjEhDvFxOZDWuC1Q8B+zaM6u8b5UsinCvWFcf5Jotnlb7LzWtS2/M0+r8paYVzGW1uoqgf7tjT+EQlfsG7v2bB1bwIelD/n0DKwiQJCL/voG9oc8DMwLqfiNjXnSRQYqRJfn9KiiJtFEx2BTya6Jbcb75k1N5yVvkC9X+JhlDdzjxZ670xl7znb++NfEbUl7lqJq+4oC/nUzIrWry7TInhearX9egt98+fJCALUQr69BH82uqypf3v31VVb7qKhp6/tILywuhHM+QjQBGS1I3I0Vd6jHDDbs76mIDaIbqKvKJViaIdBoEgjzMgQBkuN3SzDZ5oFG402P2OMfrRRJM12ppH0iYE941oBSIMBuYYjiz9VmmWX+M3EjdCL2lXs5VuIJwa+y81speMw7y7Cb8UUapFjl/datGqoRHAa1SU1rGNTS4qMeMSshrq55cwk5ajiexG8VP/I8gJXIlddXxflGay0JrboscsdBdW1DGk2Ue8i2+K6P4mp9/EQ/KDOi38J/q69Sl8io2rqxsZkY0pHrLLbrasexLgUW+IGrLNIPkkhZxn6TL7H0L2sYgGkpiTB211d2EBXuExexmCYIVXrAw968wrBHvLqlZ5WjCVZgadu5R5WmJxE6pKXWAtGGJyrdMK5PUVvB9ItV0OKoZC5klqtxKgTSOoy9iL4qq0LkEW+xy1KbEqFOtPd33BzbeOjKcus7cGC6VrBF7GpopnihR8vVsKt+g7mq69GKr7EfDiTd3OLPM7DP8AzOoc0WdOr443xSfbJ2HpkX+MByBn92WIsXlVlaBzJ30ZHbKlKVgMumTZRfy4EC17/nMCeObxvY2xeyQWCayEterCbjpm+SUtZ6L1bWW2WLdviEV3hy/fvn26IJUVOeHB2/fitKdvBTYbc1mBWHaDpaoN0R9+P5HtIb9KDoLdkH49ubGLcFywd6DEVe0oXFXkqEE//B5wHy8fLNK4mygII5BiX0Y6o/FCXndkOlX1SIPBsI0yYG845yXU8ZX9oGR6bH3ZiurYvs+I8ejEywUGUpofuS1gI5wueTGlMbtTl/YFIZOchzL5uEd1bwGXXVpTXKeCD9g1nvbi2xM3aaaSws6EXDs33hzN3zyyQ0jlSqn1VVBDpSTfzGzNuOhioBodVWEa+D7U6s8g+bXs5CUpNK6Jaj9is2XpRP4Q8KBSqLeIrs9hr9wS8wb4pe4vzFrWLt8D2Yjg/zVbQgo1zDKxPV8gbnBdjWG1Lm+FvMURlpYafVXQhkUKPG1GN2EdSG94Eb+j/q0PyzO8citCRBVBAp+7O+OQ1FKLZ2mILOiBWvYgf9xm5pYLb8ZrBVpzEQ+8fnrJQkrj1/q84bMdGn3YDRKnUZZHk5YADAD32ePFrMgVSlP7IqWuKey3igLaezE3kcAzisuJl1V9Xtig0yEt/QWJsO/ucWZDFoJOyx5n1SE6ywwjiScJH0Gn+KaUf7I9STFU4tM1IjqndEouZdudfgJE7B9XY5z1QKpSyXoAuLxk/6T4nBdLzrHDM/uKUhP/tCfcmOSUhoJndswXXlUXkytq0wZOc2L9LCzNhukm2lK/5txxRjXqhlSWQbfb+ae2SDKDes794eUGlRjub1WUap2VWXZTlWoWBvazceCJ0VrjXbqTuC+9X7lR/S+ETkZxoQn9KMBkLKs355bt6jFpbfpOu93oLxc4cPV5qvOoUOQIi0czroitwwLx8fu9hWixocV6Pw37GRzhZ12uJVVo/rcYVvppuHdKs/I+pJuDb/4/Vf5L865sIJ8Uz9bsqPKV1d2vv4v")));
$g_ExceptFlex = unserialize(gzinflate(/*1551220944*/base64_decode("rRlrc9vGMX0kTdPmD/RLYYYOpJiUSJAEKSpURpZoW44eDiXlQwUVcwRO5JV49QCIVBXPtE37oZPpL+hMO/2n3d078GHJsZ3U9pDEYnfv9v0w69btZvdWdGvbade2uyXJ/5gLyZ30M2ftC/wsu6f9wdf9gXMBTxdm6fK2Vqm/3D/ZOz/qH5+5g5OTszkU8S9L26JbB27t+pybG0fej2Vp6QuKyAty/8dya+gLam7/jws28YKvslxb4mWuMDCdS2fD3ByKTIrZZhj7ecDTTWTUAkatrYUplnmUVniUkEep4DHmzOfS2UjGCbKxfyCbqzjOlti0gU2j3S1xbxwbpc9TT4ok2zFYwGXmrJklZ8Mp+8PqzohnfYkEHSBo1r6fAMTlwRLNFtB0uqU0RhRnnVwIPbIOfMI8zaqSX7OAwOha6KdiDkHPADn9OB8GcyAauA7XdsppyGR2U91x8Z2zRm/RVg3gnUieOOkjGcJHVV7B58PbYS4CX4ISXhIqWsOyuqWzk/2T7ipuNuaEgpq24KyJ1AKUp0kaikDwNJMsSp31bcJDVdoNvKmXhzzKnI2pFBlYJo946rEEfpUeNvaUxoxUej2zZDiPjBF7nj6L0wx/l0Yx8eooNTgbfMY9gmgd4nOhQ6umL++UZ/WeU87GIq3uTI2qgQC6lIX6bIDbsuLue8wb830hTwL/iQCf3B1xLYCFmq6DAGBG2WqnYx4EZoXeoLoteKN1HIg04xGXvZLzCH8TTlNfkFD0BVG7jQYZYuSCMQLmcddjQTBk3gSO2XScW2dNhIywSdG1goXrZUc8yg8ikZ1m5EYWatgCXxiylNtN1+ceOBoKxTwvzqPsS36jD0b9NTr3YPosY846SAxEiajupDwbkJktVHCzc39AOc5qSMEzBhV8bQ4p31B+bd5znjvof3XePz2D/JAwyUIOwZdicljfFlfO2t6Ye5NTLgULxJ+4v0/M6jrVJF6UBS5a3OztGLtSshtnTX/VnfUKiCAHPM2DDLif9vfOBwfHT90n58d7ZwcnxAkt2th6NViXYnXvPBNBt/v8tI8eSjQNnYm/T5RMZAEYcsyiEZduIKLJQiQIioBHSEDs0C2azcKoplMe85mfiZD3SibmiuIRsmVp2yTDXBEh5UnrdXd3yjKeVnfoIuDwIIp7dLJ/fth3D07dPjGw701tCwae8FMi3Ns9PiaKIhmiGKDgW6d87Y7jXPZQmsTVGfjCDPHCREFx2nnLmH9o1TDqH1rWOMsSjH3gu1bCh7Rb6hFD9MJW+92TSDJ5DPY6HxxSrUJ3bLxWdyDz8zM+y7pdQkZ3s8BC5hXkgwhc1ETfWuQAQnqjJzllLuVROoJSY6ogbKInNV93C4idvpSxNKZjHhlBzHwRjYiMPKbx5su78PT17uHBvrJ3s3U3ATVtBTPTG8hYoUmwtsqtJiIqiM62RFoiCJoBrOAqOirbNVWHUnbNLS9ObghY11UMVbeEa+mCxyM/ZII02GoomMeivTEUSII1dcbd5Jm3mbA0nfrq4q2WNkruJ93NTYiUlAdX3S5Eoecy36d82LJ1euXgLdx3mzZP2RC0YjrflCDJOc66WTEh9ZKvttr3FNIWil4H2eOES5aBCYwlMba0dKMgHrI5jU2lGzhNRTY2apvw1ygiht6jUpo2lSULyhLlPedi3lLNFs3VJbou1FPhZ2Mi1cU+TbiHKTElYKE5UHphWLtZ3CFxoc1wvVxKiBY3Tzmpxm4pA1Z3vELZtq1tihZRjYLd1iDFmkAdBfp0CUSVoQW3ymQSp6tN37OzsxfuOTy6u0+hOkAarJj7Mk+oorVrWrvKJ70ALAy1TInQLkrzVR55mYgjyPRQS4G/uZJ6Cdcqsujbx8QRETZ0MOkWIRSRO9vWhgnZjB5uijc3+GARXVNXQ0iTGRjPZJTgKSfOAHtmOJ8ZRccxQTLKkcqK7aLFnRvak5xl3C0kncMr819oRMlTSLbQIWQ3qje19SXegY8nbxLqR9ptnZrvsdoc+xXrLTnmguPhTTQjhpQl2sQQ/v1whkenB8QP3cpqzdvi8j5YX4phjpJBy1GeULtdW8EqJHfWWGUI1pCchO3UNRbWEsgX0+nU2biCZmsYxxNnw4spnjvWKlbIktTZGMXxKOCERPNJp6G1fif1qMxT6dQqlOyjWH3DrSv1Vq1GxE3dw4FAGw4MXNeCT8FvvsAnQmgte/JcJ6949EJv5Qz8mght3fIX6rp2sfXUvWuHIhlEC+Nr7uYJ1hPIiJiWyVBPDg77p+DG8zcJNKBsxNGroZ0JE1cVvssKTi/pXhxdCeJL+RFq2BULUq4ax0/oxZZOcm+bFI6YZ5yc0jSEJm3V3qnG6+mNyAtbz080YOIb9I9Ozvru7v7+gCrYlqXVxZ4Nat5+fH1oHd8M94/y39FbtHELrPAc+sckjlLe7UIn/Dj2IectN+vU+LAMmtYoBdVoKLHQ/f5vv/vwPfxDMF2CX3z5/gdzGNkNjvrlR7/69cfG5g5q3Pk9vWor9H+8OH768Ue/+YhgHV1zSNMC6tenBKZS1NLgUKTwwqyoFrNeKwpSQaPafDQlUwiUapuoMgwgJRQUpRTDDJINdy6rOwqi8K27stVrDVWb3vvJT3/28/c/+MWHCtrUDvLA+cQpP/zUBKd/pN7oEvTtd//817//818Fs1WnoXShQG1dxCFCNjZf+Sj2BvDthgq9o2dbkBHKA9TsmFJRyDKY60CgOuq3pnApw9QLXJ8Xwvsotxq3a9pNXDjvkcuGQxjFBTQCagylcVyXPs5CN429CVZbmH0jLDyZp1MEKFTGMxjDx7EaB+v1Itmo2rdIXEmFVbzKpKKGa5rkEc2UeTQR2Ty3gwdSSFYUWlMp7s9/+eu3f/u7ArUUSJlDgbR631tYjaZypQOYvcaxT+OiHIGmanqZRcP2G1C2dDvmlPFSGoGCdwmL5nGs6Gk+pAoR+i2Yh/QDeFo84VGlpiSyirYbXoLOF3jFs8Iq+u63NIAiou0I+O/nD6pVY8D9ZzyA9s6oVnfU+6YOByjkTw9PHu8eYmosxjtKiVB9YJa+VIsNNcYDvyvoEqM3bpoUjV0sEz45Pnk8gKRZKanMWacxvgVmIvW80weMi4V/qRGfOhsecEqjFx6cv4Y9CY0jBVShzxMIvHAu0Ccv57soGt8t7BWcC9wZQdvufGHqX2ex2TVZkijM+tKpzoU6i1yCuL2sQDLPE8g+yrvVAN5euWSmUGHGUtS0QxLo8oqkMQ/wOck4CwO4EH6ZRtcwoSYqXDKkvYIr7tWB0C5KU/UrFNG9FFFBYWsPxAp+iGXqmyM2m8JciIAXQZ6WKs9yNuXijMFcoYyjJunVY4Z4TO21Ynd07CwHoeQBU92QCQeHxyzUat2as7/mMiWMOi0gXnIo0ziMUBGjpKg2grV5BYA+J2QR8dc/qQwIH24proQ6gYbiJq3WcF2FktGF2BTuUiywTLJk2aNVjNrS0Zys6FbczFk3ViC0hrpIs8JR1Kx8j6PcpzDIDdCI7eE0oYibhe4WxdHAKiiiJM9opUK/FHJLI09EEBjVLUMlD+ETnmrovSDWnG29SECRabhyixoCrRV0BXAISJRrIYpSdhc7TvDiqWoYY6nQO9qKd9GLBSPiX6MyVJzSWG631IIGm2XdeSHt7gjwKuZu5MtY+Kaz/qDX003bbSFXGA+hIexlMid2NNK3GndWXbkMFlsvaiHBfr2eKSKfz2hzbupRt04LABuidYnmzuJMm4EUzGfQgfqctng9/aA4Fani+y4D7X4uo3MpFEnhNEs4Sz9JQV4KboKNAVCnfEQVSxE3tfBqHMbqBNqGIvQH7mXwawi9YAXXc7Tz0pF1i1fAhaNiUdSFnogEjuFQkHyRYrDMy3hqzv1K0dg6QN5EgyZ+wMMkUzWNthe0gFLrnTJYYQ/FLG5Gw7XLAsHSYvdYp+1Gc7ETKmOBBYIkHwbCM4rzDFoe47J5b4z/OcBVSqL1Bzr/3bK3+n89hG0XOzdaOLwRu+hInxQTymsrqsIv+oAVd1gQ6drtng8OsAircKHFidW5m1SWk31p++X/AA==")));
$g_AdwareSig = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$g_PhishingSig = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$g_JSVirSig = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1551220944*/base64_decode("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")));
$g_SusDB = unserialize(gzinflate(/*1551220944*/base64_decode("S7QysKquBQA=")));
$g_SusDBPrio = unserialize(gzinflate(/*1551220944*/base64_decode("S7QysKquBQA=")));
$g_Mnemo = @array_flip(unserialize(gzinflate(/*1551220944*/base64_decode("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"))));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
    echo "#####################################################\n";
    echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
    echo "#                                                   #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
    echo "#####################################################\n";
    echo "# Warning: PHP Version < 5.3.1                      #\n";
    echo "# Some function might not work properly             #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
    echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";
    exit;
}

define('AI_VERSION', '20190226-2242');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_Structure = array();
$g_Counter   = 0;

$g_SpecificExt = false;

$g_UpdatedJsonLog    = 0;
$g_NotRead           = array();
$g_FileInfo          = array();
$g_Iframer           = array();
$g_PHPCodeInside     = array();
$g_CriticalJS        = array();
$g_Phishing          = array();
$g_Base64            = array();
$g_HeuristicDetected = array();
$g_HeuristicType     = array();
$g_UnixExec          = array();
$g_SkippedFolders    = array();
$g_UnsafeFilesFound  = array();
$g_CMS               = array();
$g_SymLinks          = array();
$g_HiddenFiles       = array();
$g_Vulnerable        = array();

$g_RegExpStat = array();

$g_TotalFolder = 0;
$g_TotalFiles  = 0;

$g_FoundTotalDirs  = 0;
$g_FoundTotalFiles = 0;

if (!isCli()) {
    $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/';
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 - 2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size', '16M');
ini_set('realpath_cache_ttl', '1200');
ini_set('pcre.backtrack_limit', '1000000');
ini_set('pcre.recursion_limit', '200000');
ini_set('pcre.jit', '1');

if (!function_exists('stripos')) {
    function stripos($par_Str, $par_Entry, $Offset = 0) {
        return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
define('CMS_BITRIX', 'Bitrix');
define('CMS_WORDPRESS', 'WordPress');
define('CMS_JOOMLA', 'Joomla');
define('CMS_DLE', 'Data Life Engine');
define('CMS_IPB', 'Invision Power Board');
define('CMS_WEBASYST', 'WebAsyst');
define('CMS_OSCOMMERCE', 'OsCommerce');
define('CMS_DRUPAL', 'Drupal');
define('CMS_MODX', 'MODX');
define('CMS_INSTANTCMS', 'Instant CMS');
define('CMS_PHPBB', 'PhpBB');
define('CMS_VBULLETIN', 'vBulletin');
define('CMS_SHOPSCRIPT', 'PHP ShopScript Premium');

define('CMS_VERSION_UNDEFINED', '0.0');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class CmsVersionDetector {
    private $root_path;
    private $versions;
    private $types;
    
    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions  = array();
        $this->types     = array();
        
        $version = '';
        
        $dir_list   = $this->getDirList($root_path);
        $dir_list[] = $root_path;
        
        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
                $this->addCms(CMS_BITRIX, $version);
            }
            
            if ($this->checkWordpress($dir, $version)) {
                $this->addCms(CMS_WORDPRESS, $version);
            }
            
            if ($this->checkJoomla($dir, $version)) {
                $this->addCms(CMS_JOOMLA, $version);
            }
            
            if ($this->checkDle($dir, $version)) {
                $this->addCms(CMS_DLE, $version);
            }
            
            if ($this->checkIpb($dir, $version)) {
                $this->addCms(CMS_IPB, $version);
            }
            
            if ($this->checkWebAsyst($dir, $version)) {
                $this->addCms(CMS_WEBASYST, $version);
            }
            
            if ($this->checkOsCommerce($dir, $version)) {
                $this->addCms(CMS_OSCOMMERCE, $version);
            }
            
            if ($this->checkDrupal($dir, $version)) {
                $this->addCms(CMS_DRUPAL, $version);
            }
            
            if ($this->checkMODX($dir, $version)) {
                $this->addCms(CMS_MODX, $version);
            }
            
            if ($this->checkInstantCms($dir, $version)) {
                $this->addCms(CMS_INSTANTCMS, $version);
            }
            
            if ($this->checkPhpBb($dir, $version)) {
                $this->addCms(CMS_PHPBB, $version);
            }
            
            if ($this->checkVBulletin($dir, $version)) {
                $this->addCms(CMS_VBULLETIN, $version);
            }
            
            if ($this->checkPhpShopScript($dir, $version)) {
                $this->addCms(CMS_SHOPSCRIPT, $version);
            }
            
        }
    }
    
    function getDirList($target) {
        $remove      = array(
            '.',
            '..'
        );
        $directories = array_diff(scandir($target), $remove);
        
        $res = array();
        
        foreach ($directories as $value) {
            if (is_dir($target . '/' . $value)) {
                $res[] = $target . '/' . $value;
            }
        }
        
        return $res;
    }
    
    function isCms($name, $version) {
        for ($i = 0; $i < count($this->types); $i++) {
            if ((strpos($this->types[$i], $name) !== false) && (strpos($this->versions[$i], $version) !== false)) {
                return true;
            }
        }
        
        return false;
    }
    
    function getCmsList() {
        return $this->types;
    }
    
    function getCmsVersions() {
        return $this->versions;
    }
    
    function getCmsNumber() {
        return count($this->types);
    }
    
    function getCmsName($index = 0) {
        return $this->types[$index];
    }
    
    function getCmsVersion($index = 0) {
        return $this->versions[$index];
    }
    
    private function addCms($type, $version) {
        $this->types[]    = $type;
        $this->versions[] = $version;
    }
    
    private function checkBitrix($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/bitrix')) {
            $res = true;
            
            $tmp_content = @file_get_contents($this->root_path . '/bitrix/modules/main/classes/general/version.php');
            if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWordpress($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wp-admin')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/wp-includes/version.php');
            if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
        }
        
        return $res;
    }
    
    private function checkJoomla($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/libraries/joomla')) {
            $res = true;
            
            // for 1.5.x
            $tmp_content = @file_get_contents($dir . '/libraries/joomla/version.php');
            if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            // for 1.7.x
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            
            // for 2.5.x and 3.x 
            $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');
            
            if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
        }
        
        return $res;
    }
    
    private function checkDle($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/engine/engine.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
            $tmp_content = @file_get_contents($dir . '/install.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkIpb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/ips_kernel')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
            if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWebAsyst($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wbs/installer')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/license.txt');
            if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkOsCommerce($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/version.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkDrupal($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/sites/all')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
            if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . '/core/lib/Drupal.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/core/lib/Drupal.php');
            if (preg_match('|VERSION\s*=\s*\'(\d+\.\d+\.\d+)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . 'modules/system/system.info')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . 'modules/system/system.info');
            if (preg_match('|version\s*=\s*"\d+\.\d+"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkMODX($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/manager/assets')) {
            $res = true;
            
            // no way to pick up version
        }
        
        return $res;
    }
    
    private function checkInstantCms($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/plugins/p_usertab')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/index.php');
            if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkPhpBb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/acp')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/config.php');
            if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkVBulletin($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        if (file_exists($dir . '/core/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/core/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vb5_connect'];
        } else if (file_exists($dir . '/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vbulletin'];
        }
        return $res;
    }
    
    private function checkPhpShopScript($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/install/consts.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/install/consts.php');
            if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
}

/**
 * Print file
 */
function printFile() {
    die("Not Supported");
 
    $l_FileName = $_GET['fn'];
    $l_CRC      = isset($_GET['c']) ? (int) $_GET['c'] : 0;
    $l_Content  = file_get_contents($l_FileName);
    $l_FileCRC  = realCRC($l_Content);
    if ($l_FileCRC != $l_CRC) {
        echo 'Доступ запрещен.';
        exit;
    }
    
    echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false) {
    $in = crc32($full ? normal($str_in) : $str_in);
    return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli() {
    return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
    return hash('crc32b', $str);
}

function generatePassword($length = 9) {
    
    // start with a blank password
    $password = "";
    
    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";
    
    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);
    
    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
        $length = $maxlength;
    }
    
    // set up a counter for how many characters are in the password so far
    $i = 0;
    
    // add random characters to $password until $length is reached
    while ($i < $length) {
        
        // pick a random character from the possible ones
        $char = substr($possible, mt_rand(0, $maxlength - 1), 1);
        
        // have we already used this character in $password?
        if (!strstr($password, $char)) {
            // no, so it's OK to add it onto the end of whatever we've already got...
            $password .= $char;
            // ... and increase the counter by one
            $i++;
        }
        
    }
    
    // done!
    return $password;
    
}

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true) {
    if (!isCli())
        return;
    
    if (is_bool($text)) {
        $text = $text ? 'true' : 'false';
    } else if (is_null($text)) {
        $text = 'null';
    }
    if (!is_scalar($text)) {
        $text = print_r($text, true);
    }
    
    if ((!BOOL_RESULT) && (!JSON_STDOUT)) {
        @fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
    }
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File) {
    global $g_CriticalPHP, $g_Base64, $g_Phishing, $g_CriticalJS, $g_Iframer, $g_UpdatedJsonLog, $g_AddPrefix, $g_NoPrefix;
    
    $total_files  = $GLOBALS['g_FoundTotalFiles'];
    $elapsed_time = microtime(true) - START_TIME;
    $percent      = number_format($total_files ? $num * 100 / $total_files : 0, 1);
    $stat         = '';
    if ($elapsed_time >= 1) {
        $elapsed_seconds = round($elapsed_time, 0);
        $fs              = floor($num / $elapsed_seconds);
        $left_files      = $total_files - $num;
        if ($fs > 0) {
            $left_time = ($left_files / $fs); //ceil($left_files / $fs);
            $stat      = ' [Avg: ' . round($fs, 2) . ' files/s' . ($left_time > 0 ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($g_CriticalPHP) + count($g_Base64)) . '|' . (count($g_CriticalJS) + count($g_Iframer) + count($g_Phishing)) . ']';
        }
    }
    
    $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File);
    $l_FN = substr($par_File, -60);
    
    $text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
    $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
    stdOut(str_repeat(chr(8), 160) . $text, false);
    
    
    $data = array(
        'self' => __FILE__,
        'started' => AIBOLIT_START_TIME,
        'updated' => time(),
        'progress' => $percent,
        'time_elapsed' => $elapsed_seconds,
        'time_left' => round($left_time),
        'files_left' => $left_files,
        'files_total' => $total_files,
        'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160)
    );
    
    if (function_exists('aibolit_onProgressUpdate')) {
        aibolit_onProgressUpdate($data);
    }
    
    if (defined('PROGRESS_LOG_FILE') && (time() - $g_UpdatedJsonLog > 1)) {
        if (function_exists('json_encode')) {
            file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
        } else {
            file_put_contents(PROGRESS_LOG_FILE, serialize($data));
        }
        
        $g_UpdatedJsonLog = time();
    }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds) {
    $r        = '';
    $_seconds = floor($seconds);
    $ms       = $seconds - $_seconds;
    $seconds  = $_seconds;
    if ($hours = floor($seconds / 3600)) {
        $r .= $hours . (isCli() ? ' h ' : ' час ');
        $seconds = $seconds % 3600;
    }
    
    if ($minutes = floor($seconds / 60)) {
        $r .= $minutes . (isCli() ? ' m ' : ' мин ');
        $seconds = $seconds % 60;
    }
    
    if ($minutes < 3)
        $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек');
    
    return $r;
}

if (isCli()) {
    
    $cli_options = array(
        'y' => 'deobfuscate',
        'c:' => 'avdb:',
        'm:' => 'memory:',
        's:' => 'size:',
        'a' => 'all',
        'd:' => 'delay:',
        'l:' => 'list:',
        'r:' => 'report:',
        'f' => 'fast',
        'j:' => 'file:',
        'p:' => 'path:',
        'q' => 'quite',
        'e:' => 'cms:',
        'x:' => 'mode:',
        'k:' => 'skip:',
        'i:' => 'idb:',
        'n' => 'sc',
        'o:' => 'json_report:',
        't:' => 'php_report:',
        'z:' => 'progress:',
        'g:' => 'handler:',
        'b' => 'smart',
        'u:' => 'username:',
        'h' => 'help'
    );
    
    $cli_longopts = array(
        'deobfuscate',
        'avdb:',
        'cmd:',
        'noprefix:',
        'addprefix:',
        'scan:',
        'one-pass',
        'smart',
        'quarantine',
        'with-2check',
        'skip-cache',
        'username:',
        'imake',
        'icheck',
        'no-html',
        'json-stdout', 
        'listing:'
    );
    
    $cli_longopts = array_merge($cli_longopts, array_values($cli_options));
    
    $options = getopt(implode('', array_keys($cli_options)), $cli_longopts);
    
    if (isset($options['h']) OR isset($options['help'])) {
        $memory_limit = ini_get('memory_limit');
        echo <<<HELP
Revisium AI-Bolit - an Intelligent Malware File Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE      		Full path to single file to check
  -p, --path=PATH      		Directory path to scan, by default the file directory is used
                       		Current path: {$defaults['path']}
  -p, --listing=FILE      	Scan files from the listing. E.g. --listing=/tmp/myfilelist.txt
                                Use --listing=stdin to get listing from stdin stream
  -x, --mode=INT       		Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...   		Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...   		Scan only specific extensions. E.g. --scan=php,htaccess,js

  -r, --report=PATH
  -o, --json_report=FILE	Full path to create json-file with a list of found malware
  -l, --list=FILE      		Full path to create plain text file with a list of found malware
      --no-html                 Disable HTML report

      --smart                   Enable smart mode (skip cache files and optimize scanning)
  -m, --memory=SIZE    		Maximum amount of memory a script may consume. Current value: $memory_limit
                       		Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE      		Scan files are smaller than SIZE. 0 - All files. Current value: {$defaults['max_size_to_scan']}
  -d, --delay=INT      		Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -a, --all            		Scan all files (by default scan. js,. php,. html,. htaccess)
      --one-pass       		Do not calculate remaining time
      --quarantine     		Archive all malware from report
      --with-2check    		Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file	   	Integrity Check database file

  -z, --progress=FILE  		Runtime progress of scanning, saved to the file, full path required. 
  -u, --username=<username>  	Run scanner with specific user id and group id, e.g. --username=www-data
  -g, --hander=FILE    		External php handler for different events, full path to php file required.
      --cmd="command [args...]"	Run command after scanning

      --help           		Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
        exit;
    }
    
    $l_FastCli = false;

    if ((isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory'])) OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))) {
        $memory = getBytes($memory);
        if ($memory > 0) {
            $defaults['memory_limit'] = $memory;
            ini_set('memory_limit', $memory);
        }
    }
    
    
    $avdb = '';
    if ((isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb'])) OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))) {
        if (file_exists($avdb)) {
            $defaults['avdb'] = $avdb;
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)) {
        define('SCAN_FILE', $file);
    }
    
    
    if (isset($options['deobfuscate']) OR isset($options['y'])) {
        define('AI_DEOBFUSCATE', true);
    }
    
    if ((isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false) OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)) {
        
        define('PLAIN_FILE', $file);
    }
    
    if ((isset($options['listing']) AND !empty($options['listing']) AND ($listing = $options['listing']) !== false)) {
        
        if (file_exists($listing) && is_file($listing) && is_readable($listing)) {
            define('LISTING_FILE', $listing);
        }

        if ($listing == 'stdin') {
            define('LISTING_FILE', $listing);
        }
    }
    
    if ((isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false) OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)) {
        define('JSON_FILE', $file);

        if (!function_exists('json_encode')) {
           die('json_encode function is not available. Enable json extension in php.ini');
        }
    }
    
    if ((isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false) OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)) {
        define('PHP_FILE', $file);
    }
    
    if (isset($options['smart']) OR isset($options['b'])) {
        define('SMART_SCAN', 1);
    }
    
    if ((isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false) OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)) {
        if (file_exists($file)) {
            define('AIBOLIT_EXTERNAL_HANDLER', $file);
        }
    }
    
    if ((isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false) OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)) {
        define('PROGRESS_LOG_FILE', $file);
    }
    
    if ((isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false) OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)) {
        $size                         = getBytes($size);
        $defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
    }
    
    if ((isset($options['username']) AND !empty($options['username']) AND ($username = $options['username']) !== false) OR (isset($options['u']) AND !empty($options['u']) AND ($username = $options['u']) !== false)) {
        
        if (!empty($username) && ($info = posix_getpwnam($username)) !== false) {
            posix_setgid($info['gid']);
            posix_setuid($info['uid']);
            $defaults['userid']  = $info['uid'];
            $defaults['groupid'] = $info['gid'];
        } else {
            echo ('Invalid username');
            exit(-1);
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false) AND (isset($options['q']))) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['json-stdout'])) {
       define('JSON_STDOUT', true);  
    } else {
       define('JSON_STDOUT', false);  
    }

    if (isset($options['f'])) {
        $l_FastCli = true;
    }
    
    if (isset($options['q']) || isset($options['quite'])) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['x'])) {
        define('AI_EXPERT', $options['x']);
    } else if (isset($options['mode'])) {
        define('AI_EXPERT', $options['mode']);
    } else {
        define('AI_EXPERT', AI_EXPERT_MODE);
    }
    
    if (AI_EXPERT < 2) {
        $g_SpecificExt              = true;
        $defaults['scan_all_files'] = false;
    } else {
        $defaults['scan_all_files'] = true;
    }
    
    define('BOOL_RESULT', $BOOL_RESULT);
    
    if ((isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false) OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)) {
        $delay = (int) $delay;
        if (!($delay < 0)) {
            $defaults['scan_delay'] = $delay;
        }
    }
    
    if ((isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false) OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)) {
        $defaults['skip_ext'] = $ext_list;
    }
    
    if (isset($options['n']) OR isset($options['skip-cache'])) {
        $defaults['skip_cache'] = true;
    }
    
    if (isset($options['scan'])) {
        $ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
        if ($ext_list != '') {
            $l_FastCli        = true;
            $g_SensitiveFiles = explode(",", $ext_list);
            for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
                if ($g_SensitiveFiles[$i] == '.') {
                    $g_SensitiveFiles[$i] = '';
                }
            }
            
            $g_SpecificExt = true;
        }
    }
    
    
    if (isset($options['all']) OR isset($options['a'])) {
        $defaults['scan_all_files'] = true;
        $g_SpecificExt              = false;
    }
    
    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }
    
    
    if (!defined('SMART_SCAN')) {
        define('SMART_SCAN', 1);
    }
    
    if (!defined('AI_DEOBFUSCATE')) {
        define('AI_DEOBFUSCATE', false);
    }
    
    
    $l_SpecifiedPath = false;
    if ((isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false) OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)) {
        $defaults['path'] = $path;
        $l_SpecifiedPath  = true;
    }
    
    if (isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false) {
    } else {
        $g_NoPrefix = '';
    }
    
    if (isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false) {
    } else {
        $g_AddPrefix = '';
    }
    
    
    
    $l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
    $l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
    $l_SuffixReport = preg_replace('#[/\\\.\s]#', '_', $l_SuffixReport);
    $l_SuffixReport .= "-" . rand(1, 999999);
    
    if ((isset($options['report']) AND ($report = $options['report']) !== false) OR (isset($options['r']) AND ($report = $options['r']) !== false)) {
        $report = str_replace('@PATH@', $l_SuffixReport, $report);
        $report = str_replace('@RND@', rand(1, 999999), $report);
        $report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
        define('REPORT', $report);
        define('NEED_REPORT', true);
    }
    
    if (isset($options['no-html'])) {
        define('REPORT', 'no@email.com');
    }
    
    if ((isset($options['idb']) AND ($ireport = $options['idb']) !== false)) {
        $ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
        $ireport = str_replace('@RND@', rand(1, 999999), $ireport);
        $ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
        define('INTEGRITY_DB_FILE', $ireport);
    }
    
    
    defined('REPORT') OR define('REPORT', 'AI-BOLIT-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');
    
    defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));
    
    $last_arg = max(1, sizeof($_SERVER['argv']) - 1);
    if (isset($_SERVER['argv'][$last_arg])) {
        $path = $_SERVER['argv'][$last_arg];
        if (substr($path, 0, 1) != '-' AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options))) {
            $defaults['path'] = $path;
        }
    }    
    
    define('ONE_PASS', isset($options['one-pass']));
    
    define('IMAKE', isset($options['imake']));
    define('ICHECK', isset($options['icheck']));
    
    if (IMAKE && ICHECK)
        die('One of the following options must be used --imake or --icheck.');
    
} else {
    define('AI_EXPERT', AI_EXPERT_MODE);
    define('ONE_PASS', true);
}


if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));
    
    $g_DBShe       = explode("\n", base64_decode($avdb[0]));
    $gX_DBShe      = explode("\n", base64_decode($avdb[1]));
    $g_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
    $gX_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
    $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
    $g_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
    $g_AdwareSig   = explode("\n", base64_decode($avdb[6]));
    $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
    $g_JSVirSig    = explode("\n", base64_decode($avdb[8]));
    $gX_JSVirSig   = explode("\n", base64_decode($avdb[9]));
    $g_SusDB       = explode("\n", base64_decode($avdb[10]));
    $g_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
    $g_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
    $g_Mnemo    = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));
    
    if (count($g_DBShe) <= 1) {
        $g_DBShe = array();
    }
    
    if (count($gX_DBShe) <= 1) {
        $gX_DBShe = array();
    }
    
    if (count($g_FlexDBShe) <= 1) {
        $g_FlexDBShe = array();
    }
    
    if (count($gX_FlexDBShe) <= 1) {
        $gX_FlexDBShe = array();
    }
    
    if (count($gXX_FlexDBShe) <= 1) {
        $gXX_FlexDBShe = array();
    }
    
    if (count($g_ExceptFlex) <= 1) {
        $g_ExceptFlex = array();
    }
    
    if (count($g_AdwareSig) <= 1) {
        $g_AdwareSig = array();
    }
    
    if (count($g_PhishingSig) <= 1) {
        $g_PhishingSig = array();
    }
    
    if (count($gX_JSVirSig) <= 1) {
        $gX_JSVirSig = array();
    }
    
    if (count($g_JSVirSig) <= 1) {
        $g_JSVirSig = array();
    }
    
    if (count($g_SusDB) <= 1) {
        $g_SusDB = array();
    }
    
    if (count($g_SusDBPrio) <= 1) {
        $g_SusDBPrio = array();
    }
    
    stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
    $gX_FlexDBShe  = array();
    $gXX_FlexDBShe = array();
    $gX_JSVirSig   = array();
}

if (isset($defaults['userid'])) {
    stdOut('Running from ' . $defaults['userid'] . ':' . $defaults['groupid']);
}

stdOut('Malware signatures: ' . (count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe)));

if ($g_SpecificExt) {
    stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

if (!DEBUG_PERFORMANCE) {
    OptimizeSignatures();
} else {
    stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) {
    define('PLAIN_FILE', '');
}

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 120);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
    include_once(AIBOLIT_EXTERNAL_HANDLER);
    stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
    if (function_exists("aibolit_onStart")) {
        aibolit_onStart();
    }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
    $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
    $defaults['scan_all_files'] = 0;
}

if (!isCli()) {
    define('ICHECK', isset($_GET['icheck']));
    define('IMAKE', isset($_GET['imake']));
    
    define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
    ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH) {
    if (isCli()) {
        die(stdOut("Directory '{$defaults['path']}' not found!"));
    }
} elseif (!is_readable(ROOT_PATH)) {
    if (isCli()) {
        die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
    }
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT)) {
    $report      = str_replace('\\', '/', REPORT);
    $abs         = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
    $report      = array_values(array_filter(explode('/', $report)));
    $report_file = array_pop($report);
    $report_path = realpath($abs . implode(DIR_SEPARATOR, $report));
    
    define('REPORT_FILE', $report_file);
    define('REPORT_PATH', $report_path);
    
    if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE)) {
        @unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
    }
}

if (defined('REPORT_PATH')) {
    $l_ReportDirName = REPORT_PATH;
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000, 9999) . '.txt');

if (function_exists('phpinfo')) {
    ob_start();
    phpinfo();
    $l_PhpInfo = ob_get_contents();
    ob_end_clean();
    
    $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
    preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
    $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>';
} else {
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email) {
    $email = preg_split('#[,\s;]#', $email, -1, PREG_SPLIT_NO_EMPTY);
    $r     = array();
    for ($i = 0, $size = sizeof($email); $i < $size; $i++) {
        if (function_exists('filter_var')) {
            if (filter_var($email[$i], FILTER_VALIDATE_EMAIL)) {
                $r[] = $email[$i];
            }
        } else {
            // for PHP4
            if (strpos($email[$i], '@') !== false) {
                $r[] = $email[$i];
            }
        }
    }
    return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val) {
    $val  = trim($val);
    $last = strtolower($val{strlen($val) - 1});
    switch ($last) {
        case 't':
            $val *= 1024;
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }
    return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites) {
    if ($bites < 1024) {
        return $bites . ' b';
    } elseif (($kb = $bites / 1024) < 1024) {
        return number_format($kb, 2) . ' Kb';
    } elseif (($mb = $kb / 1024) < 1024) {
        return number_format($mb, 2) . ' Mb';
    } elseif (($gb = $mb / 1024) < 1024) {
        return number_format($gb, 2) . ' Gb';
    } else {
        return number_format($gb / 1024, 2) . 'Tb';
    }
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
    global $g_IgnoreList;
    
    for ($i = 0; $i < count($g_IgnoreList); $i++) {
        if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
            if ($par_CRC == $g_IgnoreList[$i][1]) {
                return true;
            }
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
    global $g_AddPrefix, $g_NoPrefix;
    if ($replace_path) {
        $lines = explode("\n", $par_Str);
        array_walk($lines, function(&$n) {
            global $g_AddPrefix, $g_NoPrefix;
            $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
        });
        
        $par_Str = implode("\n", $lines);
    }
    
    return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
    global $g_AddPrefix, $g_NoPrefix;
    array_walk($par_Arr, function(&$n) {
        global $g_AddPrefix, $g_NoPrefix;
        $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
    });
    
    return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function getRawJsonVuln($par_List) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos      = $par_List[$i]['ndx'];
        $res['fn']  = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        $res['sig'] = $par_List[$i]['id'];
        
        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['sigid'] = 'vuln_' . md5($g_Structure['n'][$l_Pos] . $par_List[$i]['id']);
        
        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function getRawJson($par_List, $par_Details = null, $par_SigId = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix, $g_Mnemo;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_n' . rand(1000000, 9000000);
        }
                
        $l_Pos     = $par_List[$i];
        $res['fn'] = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        if ($par_Details != null) {
            $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
            $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
            $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
            $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
            $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);            
        }
        
        $res['sig'] = convertToUTF8($res['sig']);

        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['hash']  = $g_Structure['crc'][$l_Pos];
        $res['sigid'] = $l_SigId;
        
        if (isset($par_SigId) && isset($g_Mnemo[$par_SigId[$i]])) {
           $res['sn'] = $g_Mnemo[$par_SigId[$i]]; 
        } else {
           $res['sn'] = ''; 
        }

        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $i = 0;
    
    if ($par_TableName == null) {
        $par_TableName = 'table_' . rand(1000000, 9000000);
    }
    
    $l_Result = '';
    $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";
    
    $l_Result .= "<thead><tr class=\"tbgh" . ($i % 2) . "\">";
    $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
    $l_Result .= "<th>" . AI_STR_005 . "</th>";
    $l_Result .= "<th>" . AI_STR_006 . "</th>";
    $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
    $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    
    $l_Result .= "</tr></thead><tbody>";
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_z' . rand(1000000, 9000000);
        }
        
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        $l_Creat = $g_Structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['c'][$l_Pos]) : '-';
        $l_Modif = $g_Structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['m'][$l_Pos]) : '-';
        $l_Size  = $g_Structure['s'][$l_Pos] > 0 ? bytes2Human($g_Structure['s'][$l_Pos]) : '-';
        
        if ($par_Details != null) {
            $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
            $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
            $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);
            
            $l_Body = '<div class="details">';
            
            if ($par_SigId != null) {
                $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
            }
            
            $l_Body .= $l_WithMarker . '</div>';
        } else {
            $l_Body = '';
        }
        
        $l_Result .= '<tr class="tbg' . ($i % 2) . '" o="' . $l_SigId . '">';
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
        } else {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]])) . '</a></div></td>';
        }
        
        $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['crc'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['m'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
        $l_Result .= '</tr>';
        
    }
    
    $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $l_Result = "";
    
    $l_Src = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;'
    );
    $l_Dst = array(
        '"',
        '<',
        '>',
        '&',
        '\''
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        
        if ($par_Details != null) {
            
            $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
            $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
            $l_Body = str_replace($l_Src, $l_Dst, $l_Body);
            
        } else {
            $l_Body = '';
        }
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
        } else {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]]) . "\n";
        }
        
    }
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
    if (preg_match('|<tr><td class="e">\s*' . $par_Name . '\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
        return str_replace('no value', '', strip_tags($l_Result[1]));
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
    $l_PhpInfoSystem    = extractValue($par_Str, 'System');
    $l_PhpPHPAPI        = extractValue($par_Str, 'Server API');
    $l_AllowUrlFOpen    = extractValue($par_Str, 'allow_url_fopen');
    $l_AllowUrlInclude  = extractValue($par_Str, 'allow_url_include');
    $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
    $l_DisplayErrors    = extractValue($par_Str, 'display_errors');
    $l_ErrorReporting   = extractValue($par_Str, 'error_reporting');
    $l_ExposePHP        = extractValue($par_Str, 'expose_php');
    $l_LogErrors        = extractValue($par_Str, 'log_errors');
    $l_MQGPC            = extractValue($par_Str, 'magic_quotes_gpc');
    $l_MQRT             = extractValue($par_Str, 'magic_quotes_runtime');
    $l_OpenBaseDir      = extractValue($par_Str, 'open_basedir');
    $l_RegisterGlobals  = extractValue($par_Str, 'register_globals');
    $l_SafeMode         = extractValue($par_Str, 'safe_mode');
        
    $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
    $l_OpenBaseDir      = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);
    
    $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
    $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
    $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI . '</span><br/>';
    $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen . '</span><br/>';
    $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude . '</span><br/>';
    $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction . '</span><br/>';
    $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors . '</span><br/>';
    $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting . '</span><br/>';
    $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP . '</span><br/>';
    $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
    $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC . '</span><br/>';
    $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT . '</span><br/>';
    $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
    $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';
    
    if (phpversion() < '5.3.0') {
        $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode . '</span><br/>';
    }
    
    return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
function addSlash($dir) {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
    if (!DEBUG_MODE) {
        return;
    }
    
    $l_MemInfo = ' ';
    if (function_exists('memory_get_usage')) {
        $l_MemInfo .= ' curmem=' . bytes2Human(memory_get_usage());
    }
    
    if (function_exists('memory_get_peak_usage')) {
        $l_MemInfo .= ' maxmem=' . bytes2Human(memory_get_peak_usage());
    }
    
    stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, $g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;
    
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    $l_SkipSample = array();
    
    QCR_Debug('Scan ' . $l_RootDir);
    
    $l_QuotedSeparator = quotemeta(DIR_SEPARATOR);
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type = filetype($l_FileName);
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && $l_Type != "dir") {                
                continue;
            }
            
            $l_Ext   = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
            $l_IsDir = is_dir($l_FileName);
            
            if (in_array($l_Ext, $g_SuspiciousFiles)) {
            }
            
            // which files should be scanned
            $l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));
            
            if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                if (ONE_PASS) {
                    $g_Structure['n'][$g_Counter] = $l_FileName . DIR_SEPARATOR;
                } else {
                    $l_Buffer .= $l_FileName . DIR_SEPARATOR . "\n";
                }
                
                $l_DirCounter++;
                
                if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $g_Doorway[]  = $l_SourceDirIndex;
                    $l_DirCounter = -655360;
                }
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_ScanDirectories($l_FileName);
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    if (in_array($l_Ext, $g_ShortListExt)) {
                        $l_DoorwayFilesCounter++;
                        
                        if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                            $g_Doorway[]           = $l_SourceDirIndex;
                            $l_DoorwayFilesCounter = -655360;
                        }
                    }
                    
                    if (ONE_PASS) {
                        QCR_ScanFile($l_FileName, $g_Counter++);
                    } else {
                        $l_Buffer .= $l_FileName . "\n";
                    }
                    
                    $g_Counter++;
                }
            }
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
//echo "\n *********** --------------------------------------------------------\n";

    $l_MaxChars = MAX_PREVIEW_LEN;

    $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

    $l_MaxLen   = strlen($par_Content);
    $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
    $l_MinPos   = max(0, $par_Pos - $l_MaxChars);
    
    $l_FoundStart = substr($par_Content, 0, $par_Pos);
    $l_FoundStart = str_replace("\r", '', $l_FoundStart);
    $l_LineNo     = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

//echo "\nMinPos=" . $l_MinPos . " Pos=" . $par_Pos . " l_RightPos=" . $l_RightPos . "\n";
//var_dump($par_Content);
//echo "\n-----------------------------------------------------\n";

                                                                                                                                                      
    $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);
    
    $l_Res = makeSafeFn(UnwrapObfu($l_Res));

    $l_Res = str_replace('~', ' ', $l_Res);

    $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);
      
    $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);
    
//echo "\nFinal:\n";
//var_dump($l_Res);
//echo "\n-----------------------------------------------------\n";
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(hexdec($escaped[1]));
}
function escapedOctDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(octdec($escaped[1]));
}
function escapedDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr($escaped[1]);
}

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
    define('T_ML_COMMENT', T_COMMENT);
} else {
    define('T_DOC_COMMENT', T_ML_COMMENT);
}

function UnwrapObfu($par_Content) {
    $GLOBALS['g_EncObfu'] = 0;
    
    $search      = array(
        ' ;',
        ' =',
        ' ,',
        ' .',
        ' (',
        ' )',
        ' {',
        ' }',
        '; ',
        '= ',
        ', ',
        '. ',
        '( ',
        '( ',
        '{ ',
        '} ',
        ' !',
        ' >',
        ' <',
        ' _',
        '_ ',
        '< ',
        '> ',
        ' $',
        ' %',
        '% ',
        '# ',
        ' #',
        '^ ',
        ' ^',
        ' &',
        '& ',
        ' ?',
        '? '
    );
    $replace     = array(
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        '!',
        '>',
        '<',
        '_',
        '_',
        '<',
        '>',
        '$',
        '%',
        '%',
        '#',
        '#',
        '^',
        '^',
        '&',
        '&',
        '?',
        '?'
    );
    $par_Content = str_replace('@', '', $par_Content);
    $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
    $par_Content = str_replace($search, $replace, $par_Content);
    $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) {
        return "'" . chr(intval($m[1], 0)) . "'";
    }, $par_Content);
    
    $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', 'escapedHexToHex', $par_Content);
    $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i', 'escapedOctDec', $par_Content);
    
    $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
    $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);
    
    $content = str_replace('<?$', '<?php$', $content);
    $content = str_replace('<?php', '<?php ', $content);
    
    return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define('UTF32_BIG_ENDIAN_BOM', chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define('UTF16_BIG_ENDIAN_BOM', chr(0xFE) . chr(0xFF));
define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define('UTF8_BOM', chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);
    
    if ($first3 == UTF8_BOM)
        return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM)
        return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM)
        return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM)
        return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM)
        return 'UTF-16LE';
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src) {
    if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
    global $g_UrlIgnoreList;
    
    for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
        if (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
    return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content) {
    global $g_Vulnerable, $g_CmsListDetector;
    
    
    $l_Vuln = array();
    
    $par_Filename = strtolower($par_Filename);
    
    if ((strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) && (strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)) {
        $l_Vuln['id']   = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) && (strpos($par_Content, '$format == \'\' || $format == false ||') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'joomla/filesystem/file.php') !== false) && (strpos($par_Content, '$file = rtrim($file, \'.\');') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) || (stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) || (stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) || (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
        $l_Vuln['id']   = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) || (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
        if (strpos($par_Content, 'showImageByID') === false) {
            $l_Vuln['id']   = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) || (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
        $l_Vuln['id']   = 'AFU : elFinder';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
        if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
            $l_Vuln['id']   = 'SQLI : DRUPAL : CVE-2014-3704';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
        if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
            $l_Vuln['id']   = 'AFD : MINIFY : CVE-2013-6619';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'timthumb.php') !== false) || (strpos($par_Filename, 'thumb.php') !== false) || (strpos($par_Filename, 'cache.php') !== false) || (strpos($par_Filename, '_img.php') !== false)) {
        if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false) {
            $l_Vuln['id']   = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
        if (strpos($par_Content, 'eval($form->ScriptDisplay);') !== false) {
            $l_Vuln['id']   = 'RCE : RSFORM : rsform.php, LINE 1605';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
        if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : FANCYBOX';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
        if (strpos($par_Content, 'verify nonce') === false) {
            $l_Vuln['id']   = 'AFU : Cherry Plugin';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {
        $l_Vuln['id']   = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        
        return true;
    }
    
    if (strpos($par_Filename, '/bx_1c_import.php') !== false) {
        if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
            $l_Vuln['id']   = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            
            return true;
        }
    }
    
    if (strpos($par_Filename, 'scripts/setup.php') !== false) {
        if (strpos($par_Content, 'PMA_Config') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, '/uploadify.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
            $l_Vuln['id']   = 'AFU : UPLOADIFY : CVE: 2012-1153';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
            $l_Vuln['id']   = 'AFU : https://revisium.com/ru/blog/adsmanager_afu.html';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {
        if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
            $l_Vuln['id']   = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'core/lib/drupal.php') !== false) {
        $version = '';
        if (preg_match('|VERSION\s*=\s*\'(8\.\d+\.\d+)\'|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '8.5.1', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        
        return false;
    }
    
    if (strpos($par_Filename, 'changelog.txt') !== false) {
        $version = '';
        if (preg_match('|Drupal\s+(7\.\d+),|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '7.58', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'phpmailer.php') !== false) {
        if (strpos($par_Content, 'PHPMailer') !== false) {
            $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);
            
            if ($l_Found) {
                $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                
                if ($l_Version < 2520) {
                    $l_Found = false;
                }
            }
            
            if (!$l_Found) {
                
                $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~', $par_Content, $l_Match);
                if ($l_Found) {
                    $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                    if ($l_Version < 5220) {
                        $l_Found = false;
                    }
                }
            }
            
            
            if (!$l_Found) {
                $l_Vuln['id']   = 'RCE : CVE-2016-10045, CVE-2016-10031';
                $l_Vuln['ndx']  = $par_Index;
                $g_Vulnerable[] = $l_Vuln;
                return true;
            }
        }
        
        return false;
    }
    
    
    
    
}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($par_Offset) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable;
    
    QCR_Debug('QCR_GoScan ' . $par_Offset);
    
    $i = 0;
    
    try {
        $s_file = new SplFileObject(QUEUE_FILENAME);
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        
        foreach ($s_file as $l_Filename) {
            QCR_ScanFile($l_Filename, $i++);
        }
        
        unset($s_file);
    }
    catch (Exception $e) {
        QCR_Debug($e->getMessage());
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $i = 0) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable, $g_CriticalFiles, $g_DeMapper;
    
    global $g_CRC;
    static $_files_and_ignored = 0;
    
    $l_CriticalDetected = false;
    $l_Stat             = stat($l_Filename);
    
    if (substr($l_Filename, -1) == DIR_SEPARATOR) {
        // FOLDER
        $g_Structure['n'][$i] = $l_Filename;
        $g_TotalFolder++;
        printProgress($_files_and_ignored, $l_Filename);
        return;
    }
    
    QCR_Debug('Scan file ' . $l_Filename);
    printProgress(++$_files_and_ignored, $l_Filename);
        
    // FILE
    if ((MAX_SIZE_TO_SCAN > 0 AND $l_Stat['size'] > MAX_SIZE_TO_SCAN) || ($l_Stat['size'] < 0)) {
        $g_BigFiles[] = $i;
        
        if (function_exists('aibolit_onBigFile')) {
            aibolit_onBigFile($l_Filename);
        }
        
        AddResult($l_Filename, $i);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if ((!AI_HOSTER) && in_array($l_Ext, $g_CriticalFiles)) {
            $g_CriticalPHP[]         = $i;
            $g_CriticalPHPFragment[] = "BIG FILE. SKIPPED.";
            $g_CriticalPHPSig[]      = "big_1";
        }
    } else {
        $g_TotalFiles++;
        
        $l_TSStartScan = microtime(true);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if (filetype($l_Filename) == 'file') {
            $l_Content   = @file_get_contents($l_Filename);
            $l_Unwrapped = @php_strip_whitespace($l_Filename);
        }
                
        if ((($l_Content == '') || ($l_Unwrapped == '')) && ($l_Stat['size'] > 0)) {
            $g_NotRead[] = $i;
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 'io');
            }
            AddResult('[io] ' . $l_Filename, $i);
            return;
        }

        // ignore itself
        if (strpos($l_Content, '13dbe7f574eed3339818a096b21927a8') !== false) {
           return false;
        }
        
        // unix executables
        if (strpos($l_Content, chr(127) . 'ELF') !== false) {
            // todo: add crc check 
            return;
        }
        
        $g_CRC = _hash_($l_Unwrapped);
        
        $l_UnicodeContent = detect_utf_encoding($l_Content);
        //$l_Unwrapped = $l_Content;
        
        // check vulnerability in files
        $l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content);
        
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
            } else {
                $g_NotRead[] = $i;
                if (function_exists('aibolit_onReadError')) {
                    aibolit_onReadError($l_Filename, 'ec');
                }
                AddResult('[ec] ' . $l_Filename, $i);
            }
        }
        
        // critical
        $g_SkipNextCheck = false;
        
        $l_DeobfType = '';
        if ((!AI_HOSTER) || AI_DEOBFUSCATE) {
            $l_DeobfType = getObfuscateType($l_Unwrapped);
        }
        
        if ($l_DeobfType != '') {
            $l_Unwrapped     = deobfuscate($l_Unwrapped);
            $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
        } else {
            if (DEBUG_MODE) {
                stdOut("\n...... NOT OBFUSCATED\n");
            }
        }
        
        $l_Unwrapped = UnwrapObfu($l_Unwrapped);
        
        if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId)) {
            if ($l_Ext == 'js') {
                $g_CriticalJS[]         = $i;
                $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalJSSig[]      = $l_SigId;
            } else {
                $g_CriticalPHP[]         = $i;
                $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalPHPSig[]      = $l_SigId;
            }
            
            $g_SkipNextCheck = true;
        } else {
            if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId)) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        $l_TypeDe = 0;
        
        // critical JS
        if (!$g_SkipNextCheck) {
            $l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos !== false) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        // phishing
        if (!$g_SkipNextCheck) {
            $l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos === false) {
                $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId);
            }
            
            if ($l_Pos !== false) {
                $g_Phishing[]            = $i;
                $g_PhishingFragment[]    = getFragment($l_Unwrapped, $l_Pos);
                $g_PhishingSigFragment[] = $l_SigId;
                $g_SkipNextCheck         = true;
            }
        }
        
        
        if (!$g_SkipNextCheck) {
            // warnings
            $l_Pos = '';
            
            // adware
            if (Adware($l_Filename, $l_Unwrapped, $l_Pos)) {
                $g_AdwareList[]         = $i;
                $g_AdwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $l_CriticalDetected     = true;
            }
            
            // articles
            if (stripos($l_Filename, 'article_index')) {
                $g_AdwareList[]     = $i;
                $l_CriticalDetected = true;
            }
        }
    } // end of if (!$g_SkipNextCheck) {
    
    unset($l_Unwrapped);
    unset($l_Content);
    
    //printProgress(++$_files_and_ignored, $l_Filename);
    
    $l_TSEndScan = microtime(true);
    if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
        usleep(SCAN_DELAY * 1000);
    }
    
    if ($g_SkipNextCheck || $l_CriticalDetected) {
        AddResult($l_Filename, $i);
    }
}

function AddResult($l_Filename, $i) {
    global $g_Structure, $g_CRC;
    
    $l_Stat                 = stat($l_Filename);
    $g_Structure['n'][$i]   = $l_Filename;
    $g_Structure['s'][$i]   = $l_Stat['size'];
    $g_Structure['c'][$i]   = $l_Stat['ctime'];
    $g_Structure['m'][$i]   = $l_Stat['mtime'];
    $g_Structure['crc'][$i] = $g_CRC;
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_SusDB, $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    
    $l_Res = false;
    
    if (AI_EXTRA_WARN) {
        foreach ($g_SusDB as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    return true;
                }
            }
        }
    }
    
    if (AI_EXPERT < 2) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
    }
    
    if (AI_EXPERT < 1) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
        $l_Content_lo = strtolower($l_Content);
        
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                return true;
            }
        }
    }
    
}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos) {
    global $g_AdwareSig;
    
    $l_Res = false;
    
    foreach ($g_AdwareSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos = $l_Found[0][1];
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
    global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);
    
    foreach ($g_ExceptFlex as $l_ExceptItem) {
        if (@preg_match('#' . $l_ExceptItem . '#smi', $l_FoundStrPlus, $l_Detected)) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_PhishingSig, $g_PhishFiles, $g_PhishEntries;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_PhishFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped phs file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_PhishingSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            $offset = $l_Found[0][1] + 1;
            
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_VirusFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped js file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_JSVirSig as $l_Item) {
        $offset = 0;
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gX_JSVirSig as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return $l_Pos;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
function pcre_error($par_FN, $par_Index) {
    global $g_NotRead, $g_Structure;
    
    $err = preg_last_error();
    if (($err == PREG_BACKTRACK_LIMIT_ERROR) || ($err == PREG_RECURSION_LIMIT_ERROR)) {
        if (!in_array($par_Index, $g_NotRead)) {
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 're');
            }
            $g_NotRead[] = $par_Index;
            AddResult('[re] ' . $par_FN, $par_Index);
        }
        
        return true;
    }
    
    return false;
}



////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

function get_descr_heur($type) {
    switch ($type) {
        case SUSP_MTIME:
            return AI_STR_077;
        case SUSP_PERM:
            return AI_STR_078;
        case SUSP_PHP_IN_UPLOAD:
            return AI_STR_079;
    }
    
    return "---";
}

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment, $g_CriticalFiles, $g_CriticalEntries, $g_RegExpStat;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_CriticalFiles as $l_Ext) {
            if ((strpos($l_FN, $l_Ext) !== false) && (strpos($l_FN, '.js') === false)) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    
    // if not critical - skip it 
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped file, not critical.\n";
        }
        
        return false;
    }
    
    foreach ($g_FlexDBShe as $l_Item) {
        $offset = 0;
        
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                //$l_SigId = myCheckSum($l_Item);
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    $l_Content_lo = strtolower($l_Content);
    
    foreach ($g_DBShe as $l_Item) {
        $l_Pos = strpos($l_Content_lo, $l_Item);
        if ($l_Pos !== false) {
            $l_SigId = myCheckSum($l_Item);
            
            if (DEBUG_MODE) {
                echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                
                if (DEBUG_MODE) {
                    echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
        }
    }
    
    if (AI_HOSTER)
        return false;
    
    if (AI_EXPERT > 0) {
        if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false)) {
            $l_Pos = 0;
            
            if (DEBUG_MODE) {
                echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    // detect uploaders / droppers
    if (AI_EXPERT > 1) {
        $l_Found = null;
        if ((filesize($l_FN) < 2048) && (strpos($l_FN, '.ph') !== false) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
            }
            if (DEBUG_MODE) {
                echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
    header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {
    
    $l_PassOK = false;
    if (strlen(PASS) > 8) {
        $l_PassOK = true;
    }
    
    if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found)) {
        $l_PassOK = true;
    }
    
    if (!$l_PassOK) {
        echo sprintf(AI_STR_009, generatePassword());
        exit;
    }
    
    if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
        printFile();
        exit;
    }
    
    if ($_GET['p'] != PASS) {
        $generated_pass = generatePassword();
        echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
        exit;
    }
}

if (!is_readable(ROOT_PATH)) {
    echo AI_STR_011;
    exit;
}

if (isCli()) {
    if (defined('REPORT_PATH') AND REPORT_PATH) {
        if (!is_writable(REPORT_PATH)) {
            die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
        }
        
        else if (!REPORT_FILE) {
            die2("\nCannot write report. Report filename is empty.");
        }
        
        else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file)) {
            die2("\nCannot write report. Report file '$file' exists but is not writable.");
        }
    }
}


// detect version CMS
$g_KnownCMS        = array();
$tmp_cms           = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum  = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $g_CMS[]                                                  = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
    $g_KnownCMS = array_keys($tmp_cms);
    $len        = count($g_KnownCMS);
    for ($i = 0; $i < $len; $i++) {
        if ($g_KnownCMS[$i] == strtolower(CMS_WORDPRESS))
            $g_KnownCMS[] = 'wp';
        if ($g_KnownCMS[$i] == strtolower(CMS_WEBASYST))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_IPB))
            $g_KnownCMS[] = 'ipb';
        if ($g_KnownCMS[$i] == strtolower(CMS_DLE))
            $g_KnownCMS[] = 'dle';
        if ($g_KnownCMS[$i] == strtolower(CMS_INSTANTCMS))
            $g_KnownCMS[] = 'instantcms';
        if ($g_KnownCMS[$i] == strtolower(CMS_SHOPSCRIPT))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_DRUPAL))
            $g_KnownCMS[] = 'drupal';
    }
}


$g_DirIgnoreList = array();
$g_IgnoreList    = array();
$g_UrlIgnoreList = array();
$g_KnownList     = array();

$l_IgnoreFilename    = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) {
        $g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);
    
    for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
        $g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
    }
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);
    
    for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
        $g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
    }
}


$l_SkipMask = array(
    '/template_\w{32}.css',
    '/cache/templates/.{1,150}\.tpl\.php',
    '/system/cache/templates_c/\w{1,40}\.php',
    '/assets/cache/rss/\w{1,60}',
    '/cache/minify/minify_\w{32}',
    '/cache/page/\w{32}\.php',
    '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
    '/cache/wp-cache-\d{32}\.php',
    '/cache/page/\w{32}\.php_expire',
    '/cache/page/\w{32}-cache-page-\w{32}\.php',
    '\w{32}-cache-com_content-\w{32}\.php',
    '\w{32}-cache-mod_custom-\w{32}\.php',
    '\w{32}-cache-mod_templates-\w{32}\.php',
    '\w{32}-cache-_system-\w{32}\.php',
    '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php',
    '/autoptimize/js/autoptimize_\w{32}\.js',
    '/bitrix/cache/\w{32}\.php',
    '/bitrix/cache/.{1,200}/\w{32}\.php',
    '/bitrix/cache/iblock_find/',
    '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
    '/bitrix/cache/s1/bitrix/catalog\.section/',
    '/bitrix/cache/s1/bitrix/catalog\.element/',
    '/bitrix/cache/s1/bitrix/menu/',
    '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
    '/bitrix/managed\_cache/.{1,150}/\.\w{32}\.php',
    '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
    '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
    '/smarty/compiled/SC/.{1,100}/%%.{1,200}\.php',
    '/smarty/.{1,150}\.tpl\.php',
    '/smarty/compile/.{1,150}\.tpl\.cache\.php',
    '/files/templates_c/.{1,150}\.html\.php',
    '/uploads/javascript_global/.{1,150}\.js',
    '/assets/cache/rss/\w{32}',
    'сore/cache/resource/web/resources/\d+\.cache\.php',
    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
    '/t3-assets/dev/t3/.{1,150}-cache-\w{1,20}-.{1,150}\.php',
    '/t3-assets/js/js-\w{1,30}\.js',
    '/temp/cache/SC/.{1,100}/\.cache\..{1,100}\.php',
    '/tmp/sess\_\w{32}$',
    '/assets/cache/docid\_.{1,100}\.pageCache\.php',
    '/stat/usage\_\w{1,100}\.html',
    '/stat/site\_\w{1,100}\.html',
    '/gallery/item/list/\w{1,100}\.cache\.php',
    '/core/cache/registry/.{1,100}/ext-.{1,100}\.php',
    '/core/cache/resource/shk\_/\w{1,50}\.cache\.php',
    '/cache/\w{1,40}/\w+-cache-\w+-\w{32,40}\.php',
    '/webstat/awstats.{1,150}\.txt',
    '/awstats/awstats.{1,150}\.txt',
    '/awstats/.{1,80}\.pl',
    '/awstats/.{1,80}\.html',
    '/inc/min/styles_\w+\.min\.css',
    '/inc/min/styles_\w+\.min\.js',
    '/logs/error\_log\.',
    '/logs/xferlog\.',
    '/logs/access_log\.',
    '/logs/cron\.',
    '/logs/exceptions/.{1,200}\.log$',
    '/hyper-cache/[^/]{1,50}/[^/]{1,50}/[^/]{1,50}/index\.html',
    '/mail/new/[^,]+,S=[^,]+,W=',
    '/mail/new/[^,]=,S=',
    '/application/logs/\d+/\d+/\d+\.php',
    '/sites/default/files/js/js_\w{32}\.js',
    '/yt-assets/\w{32}\.css',
    '/wp-content/cache/object/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/catalog\.section/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/simpla/design/compiled/[\w\.]{40,60}\.php',
    '/compile/\w{2}/\w{2}/\w{2}/[\w.]{40,80}\.php',
    '/sys-temp/static-cache/[^/]{1,60}/userCache/[\w\./]{40,100}\.php',
    '/session/sess_\w{32}',
    '/webstat/awstats\.[\w\./]{3,100}\.html',
    '/stat/webalizer\.current',
    '/stat/usage_\d+\.html'
);

$l_SkipSample = array();

if (SMART_SCAN) {
    $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures
if (file_exists($g_AiBolitAbsolutePath . "/ai-bolit.sig")) {
   try {
       $s_file = new SplFileObject($g_AiBolitAbsolutePath . "/ai-bolit.sig");
       $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
       foreach ($s_file as $line) {
           $g_FlexDBShe[] = preg_replace('~\G(?:[^#\\\\]+|\\\\.)*+\K#~', '\\#', $line); // escaping #
       }

       stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
       $s_file = null; // file handler is closed
   }
   catch (Exception $e) {
       QCR_Debug("Import ai-bolit.sig " . $e->getMessage());
   }
}

QCR_Debug();

$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
if ($defaults['skip_ext'] != '') {
    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
        $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
    }
    
    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
}

// scan single file
if (defined('SCAN_FILE')) {
    if (file_exists(SCAN_FILE) && is_file(SCAN_FILE) && is_readable(SCAN_FILE)) {
        stdOut("Start scanning file '" . SCAN_FILE . "'.");
        QCR_ScanFile(SCAN_FILE);
    } else {
        stdOut("Error:" . SCAN_FILE . " either is not a file or readable");
    }
} else {
    if (isset($_GET['2check'])) {
        $options['with-2check'] = 1;
    }
    
    $use_doublecheck = isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE);
    $use_listingfile = defined('LISTING_FILE');
    
    // scan list of files from file
    if (!(ICHECK || IMAKE) && ($use_doublecheck || $use_listingfile)) {
        if ($use_doublecheck) {
            $listing = DOUBLECHECK_FILE;
        } else {
            if ($use_listingfile) {
                $listing = LISTING_FILE;
            }
        }
        
        stdOut("Start scanning the list from '" . $listing . "'.\n");

        if ($listing == 'stdin') {
           $lines = explode("\n", getStdin());
        } else {
           $lines = file($listing);
        }

        for ($i = 0, $size = count($lines); $i < $size; $i++) {
            $lines[$i] = trim($lines[$i]);
            if (empty($lines[$i]))
                unset($lines[$i]);
        }
        
        $i = 0;
        if ($use_doublecheck) {
            /* skip first line with <?php die("Forbidden"); ?> */
            unset($lines[0]);
            $i = 1;
        }
        
        $g_FoundTotalFiles = count($lines);
        foreach ($lines as $l_FN) {
            is_dir($l_FN) && $g_TotalFolder++;
            printProgress($i++, $l_FN);
            $BOOL_RESULT = true; // display disable
            is_file($l_FN) && QCR_ScanFile($l_FN, $i);
            $BOOL_RESULT = false; // display enable
        }
        
        $g_FoundTotalDirs  = $g_TotalFolder;
        $g_FoundTotalFiles = $g_TotalFiles;
        
    } else {
        // scan whole file system
        stdOut("Start scanning '" . ROOT_PATH . "'.\n");
        
        file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
        if (ICHECK || IMAKE) {
            // INTEGRITY CHECK
            IMAKE and unlink(INTEGRITY_DB_FILE);
            ICHECK and load_integrity_db();
            QCR_IntegrityCheck(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
            if (IMAKE)
                exit(0);
            if (ICHECK) {
                $i       = $g_Counter;
                $g_CRC   = 0;
                $changes = array();
                $ref =& $g_IntegrityDB;
                foreach ($g_IntegrityDB as $l_FileName => $type) {
                    unset($g_IntegrityDB[$l_FileName]);
                    $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
                    if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                        continue;
                    }
                    for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                        if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                            continue 2;
                        }
                    }
                    $type = in_array($type, array(
                        'added',
                        'modified'
                    )) ? $type : 'deleted';
                    $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
                    $changes[$type][] = ++$i;
                    AddResult($l_FileName, $i);
                }
                $g_FoundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
                stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
            }
            
        } else {
            QCR_ScanDirectories(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
        }
        
        QCR_Debug();
        stdOut(str_repeat(' ', 160), false);
        QCR_GoScan(0);
        unlink(QUEUE_FILENAME);
        if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE))
            @unlink(PROGRESS_LOG_FILE);
    }
}

QCR_Debug();

if (true) {
    $g_HeuristicDetected = array();
    $g_Iframer           = array();
    $g_Base64            = array();
}


// whitelist

$snum = 0;
$list = check_whitelist($g_Structure['crc'], $snum);

foreach (array(
    'g_CriticalPHP',
    'g_CriticalJS',
    'g_Iframer',
    'g_Base64',
    'g_Phishing',
    'g_AdwareList',
    'g_Redirect'
) as $p) {
    if (empty($$p))
        continue;
    
    $p_Fragment = $p . "Fragment";
    $p_Sig      = $p . "Sig";
    if ($p == 'g_Redirect')
        $p_Fragment = $p . "PHPFragment";
    if ($p == 'g_Phishing')
        $p_Sig = $p . "SigFragment";
    
    $count = count($$p);
    for ($i = 0; $i < $count; $i++) {
        $id = "{${$p}[$i]}";
        if (in_array($g_Structure['crc'][$id], $list)) {
            unset($GLOBALS[$p][$i]);
            unset($GLOBALS[$p_Sig][$i]);
            unset($GLOBALS[$p_Fragment][$i]);
        }
    }
    
    $$p          = array_values($$p);
    $$p_Fragment = array_values($$p_Fragment);
    if (!empty($$p_Sig))
        $$p_Sig = array_values($$p_Sig);
}


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
    $g_IframerFragment       = array();
    $g_Iframer               = array();
    $g_Redirect              = array();
    $g_Doorway               = array();
    $g_EmptyLink             = array();
    $g_HeuristicType         = array();
    $g_HeuristicDetected     = array();
    $g_WarningPHP            = array();
    $g_AdwareList            = array();
    $g_Phishing              = array();
    $g_PHPCodeInside         = array();
    $g_PHPCodeInsideFragment = array();
    $g_WarningPHPFragment    = array();
    $g_WarningPHPSig         = array();
    $g_BigFiles              = array();
    $g_RedirectPHPFragment   = array();
    $g_EmptyLinkSrc          = array();
    $g_Base64Fragment        = array();
    $g_UnixExec              = array();
    $g_PhishingSigFragment   = array();
    $g_PhishingFragment      = array();
    $g_PhishingSig           = array();
    $g_IframerFragment       = array();
    $g_CMS                   = array();
    $g_AdwareListFragment    = array();
}

if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
    if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_PhishingSig) > 0)) {
        exit(2);
    } else {
        exit(0);
    }
}
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $g_TotalFolder, $g_TotalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE))
    if (isset($options['with-2check']) || isset($options['quarantine']))
        if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR (count($g_Iframer) > 0) OR (count($g_UnixExec))) {
            if (!file_exists(DOUBLECHECK_FILE)) {
                if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
                    fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");
                    
                    $l_CurrPath = dirname(__FILE__);
                    
                    if (!isset($g_CriticalPHP)) {
                        $g_CriticalPHP = array();
                    }
                    if (!isset($g_CriticalJS)) {
                        $g_CriticalJS = array();
                    }
                    if (!isset($g_Iframer)) {
                        $g_Iframer = array();
                    }
                    if (!isset($g_Base64)) {
                        $g_Base64 = array();
                    }
                    if (!isset($g_Phishing)) {
                        $g_Phishing = array();
                    }
                    if (!isset($g_AdwareList)) {
                        $g_AdwareList = array();
                    }
                    if (!isset($g_Redirect)) {
                        $g_Redirect = array();
                    }
                    
                    $tmpIndex = array_merge($g_CriticalPHP, $g_CriticalJS, $g_Phishing, $g_Base64, $g_Iframer, $g_AdwareList, $g_Redirect);
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        $tmpIndex[$i] = str_replace($l_CurrPath, '.', $g_Structure['n'][$tmpIndex[$i]]);
                    }
                    
                    for ($i = 0; $i < count($g_UnixExec); $i++) {
                        $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
                    }
                    
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        fputs($l_FH, $tmpIndex[$i] . "\n");
                    }
                    
                    fclose($l_FH);
                } else {
                    stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
                }
            } else {
                stdOut(DOUBLECHECK_FILE . ' already exists.');
                if (AI_STR_044 != '')
                    $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
            }
            
        }

////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($g_Redirect) > 0) {
    $l_Summary .= makeSummary(AI_STR_059, count($g_Redirect), "crit");
}

if (count($g_CriticalPHP) > 0) {
    $l_Summary .= makeSummary(AI_STR_060, count($g_CriticalPHP), "crit");
}

if (count($g_CriticalJS) > 0) {
    $l_Summary .= makeSummary(AI_STR_061, count($g_CriticalJS), "crit");
}

if (count($g_Phishing) > 0) {
    $l_Summary .= makeSummary(AI_STR_062, count($g_Phishing), "crit");
}

if (count($g_NotRead) > 0) {
    $l_Summary .= makeSummary(AI_STR_066, count($g_NotRead), "crit");
}

if (count($g_BigFiles) > 0) {
    $l_Summary .= makeSummary(AI_STR_065, count($g_BigFiles), "warn");
}

if (count($g_SymLinks) > 0) {
    $l_Summary .= makeSummary(AI_STR_069, count($g_SymLinks), "warn");
}

$l_Summary .= "</table>";

$l_ArraySummary                      = array();
$l_ArraySummary["redirect"]          = count($g_Redirect);
$l_ArraySummary["critical_php"]      = count($g_CriticalPHP);
$l_ArraySummary["critical_js"]       = count($g_CriticalJS);
$l_ArraySummary["phishing"]          = count($g_Phishing);
$l_ArraySummary["unix_exec"]         = 0; // count($g_UnixExec);
$l_ArraySummary["iframes"]           = 0; // count($g_Iframer);
$l_ArraySummary["not_read"]          = count($g_NotRead);
$l_ArraySummary["base64"]            = 0; // count($g_Base64);
$l_ArraySummary["heuristics"]        = 0; // count($g_HeuristicDetected);
$l_ArraySummary["symlinks"]          = count($g_SymLinks);
$l_ArraySummary["big_files_skipped"] = count($g_BigFiles);

if (function_exists('json_encode')) {
    $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->";
}

$l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

$l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);

$l_Result .= AI_STR_015;

$l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);

////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
    $l_HostName = gethostname();
} else {
    $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit (https://revisium.com/ai/) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName . "\n\n";

$l_RawReport = array();

$l_RawReport['summary'] = array(
    'scan_path' => $defaults['path'],
    'report_time' => time(),
    'scan_time' => round(microtime(true) - START_TIME, 1),
    'total_files' => $g_FoundTotalFiles,
    'counters' => $l_ArraySummary,
    'ai_version' => AI_VERSION
);

if (!AI_HOSTER) {
    stdOut("Building list of vulnerable scripts " . count($g_Vulnerable));
    
    if (count($g_Vulnerable) > 0) {
        $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($g_Vulnerable) . ')</div><div class="crit">';
        foreach ($g_Vulnerable as $l_Item) {
            $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
            $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($g_Structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
        }
        
        $l_Result .= '</div><p>' . PHP_EOL;
        $l_PlainResult .= "\n";
    }
}


stdOut("Building list of shells " . count($g_CriticalPHP));

$l_RawReport['vulners'] = getRawJsonVuln($g_Vulnerable);

if (count($g_CriticalPHP) > 0) {
    $g_CriticalPHP              = array_slice($g_CriticalPHP, 0, 15000);
    $l_RawReport['php_malware'] = getRawJson($g_CriticalPHP, $g_CriticalPHPFragment, $g_CriticalPHPSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($g_CriticalPHP) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit');
    $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit') . "\n";
    $l_Result .= '</div>' . PHP_EOL;
    
    $l_ShowOffer = true;
} else {
    $l_Result .= '<div class="ok"><b>' . AI_STR_017 . '</b></div>';
}

stdOut("Building list of js " . count($g_CriticalJS));

if (count($g_CriticalJS) > 0) {
    $g_CriticalJS              = array_slice($g_CriticalJS, 0, 15000);
    $l_RawReport['js_malware'] = getRawJson($g_CriticalJS, $g_CriticalJSFragment, $g_CriticalJSSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($g_CriticalJS) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir');
    $l_PlainResult .= '[CLIENT MALWARE / JS]' . "\n" . printPlainList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir') . "\n";
    $l_Result .= "</div>" . PHP_EOL;
    
    $l_ShowOffer = true;
}

stdOut("Building list of unread files " . count($g_NotRead));

if (count($g_NotRead) > 0) {
    $g_NotRead               = array_slice($g_NotRead, 0, AIBOLIT_MAX_NUMBER);
    $l_RawReport['not_read'] = $g_NotRead;
    $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($g_NotRead) . ')</div><div class="crit">';
    $l_Result .= printList($g_NotRead);
    $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
    $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($g_NotRead) . "\n\n";
}

if (!AI_HOSTER) {
    stdOut("Building list of phishing pages " . count($g_Phishing));
    
    if (count($g_Phishing) > 0) {
        $l_RawReport['phishing'] = getRawJson($g_Phishing, $g_PhishingFragment, $g_PhishingSigFragment);
        $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($g_Phishing) . ')</div><div class="crit">';
        $l_Result .= printList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir');
        $l_PlainResult .= '[PHISHING]' . "\n" . printPlainList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir') . "\n";
        $l_Result .= "</div>" . PHP_EOL;
        
        $l_ShowOffer = true;
    }
    
    stdOut("Building list of redirects " . count($g_Redirect));
    if (count($g_Redirect) > 0) {
        $l_RawReport['redirect'] = getRawJson($g_Redirect, $g_RedirectPHPFragment);
        $l_ShowOffer             = true;
        $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($g_Redirect) . ')</div><div class="crit">';
        $l_Result .= printList($g_Redirect, $g_RedirectPHPFragment, true);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of symlinks " . count($g_SymLinks));
    
    if (count($g_SymLinks) > 0) {
        $g_SymLinks               = array_slice($g_SymLinks, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['sym_links'] = $g_SymLinks;
        $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($g_SymLinks) . ')</div><div class="crit">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SymLinks), true));
        $l_Result .= "</div><div class=\"spacer\"></div>";
    }
    
}

////////////////////////////////////
if (!AI_HOSTER) {
    $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($g_BigFiles) + count($g_PHPCodeInside) + count($g_AdwareList) + count($g_EmptyLink) + count($g_Doorway) + (count($g_WarningPHP[0]) + count($g_WarningPHP[1]) + count($g_SkippedFolders));
    
    if ($l_WarningsNum > 0) {
        $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
    }
    
    stdOut("Building list of adware " . count($g_AdwareList));
    
    if (count($g_AdwareList) > 0) {
        $l_RawReport['adware'] = getRawJson($g_AdwareList, $g_AdwareListFragment);
        $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
        $l_Result .= printList($g_AdwareList, $g_AdwareListFragment, true);
        $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($g_AdwareList, $g_AdwareListFragment, true) . "\n";
        $l_Result .= "</div>" . PHP_EOL;        
    }
    
    stdOut("Building list of bigfiles " . count($g_BigFiles));
    $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
    $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');
    
    if (count($g_BigFiles) > 0) {
        $g_BigFiles               = array_slice($g_BigFiles, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['big_files'] = getRawJson($g_BigFiles);
        $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
        $l_Result .= printList($g_BigFiles);
        $l_Result .= "</div>";
        $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($g_BigFiles) . "\n\n";
    }
    
    stdOut("Building list of doorways " . count($g_Doorway));
    
    if ((count($g_Doorway) > 0) && (($defaults['report_mask'] & REPORT_MASK_DOORWAYS) == REPORT_MASK_DOORWAYS)) {
        $g_Doorway              = array_slice($g_Doorway, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['doorway'] = getRawJson($g_Doorway);
        $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
        $l_Result .= printList($g_Doorway);
        $l_Result .= "</div>" . PHP_EOL;
        
    }
    
    if (count($g_CMS) > 0) {
        $l_RawReport['cms'] = $g_CMS;
        $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_CMS)));
        $l_Result .= "</div>";
    }
}

if (ICHECK) {
    $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";
    
    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['modifiedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
    $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
    $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
    $l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
    $l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)), date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli()) {
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '') {
    die2('Report not written.');
}

// write plain text result
if (PLAIN_FILE != '') {
    
    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);
    
    if ($l_FH = fopen(PLAIN_FILE, "w")) {
        fputs($l_FH, $l_PlainResult);
        fclose($l_FH);
    }
}

// write json result
if (defined('JSON_FILE')) {
    $res = @json_encode($l_RawReport);
    if ($l_FH = fopen(JSON_FILE, "w")) {
        fputs($l_FH, $res);
        fclose($l_FH);
    }

    if (JSON_STDOUT) {
       echo $res;
    }
}

// write serialized result
if (defined('PHP_FILE')) {
    if ($l_FH = fopen(PHP_FILE, "w")) {
        fputs($l_FH, serialize($l_RawReport));
        fclose($l_FH);
    }
}

$emails = getEmails(REPORT);

if (!$emails) {
    if ($l_FH = fopen($file, "w")) {
        fputs($l_FH, $l_Template);
        fclose($l_FH);
        stdOut("\nReport written to '$file'.");
    } else {
        stdOut("\nCannot create '$file'.");
    }
} else {
    $headers = array(
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : 'AI-Bolit@myhost')
    );
    
    for ($i = 0, $size = sizeof($emails); $i < $size; $i++) {
        //$res = @mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
    }
    
    if ($res) {
       stdOut("\nReport sended to " . implode(', ', $emails));
    }
}

$time_taken = microtime(true) - START_TIME;
$time_taken = number_format($time_taken, 5);

stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
    $keys = array_keys($g_RegExpStat);
    for ($i = 0; $i < count($keys); $i++) {
        $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
    }
    
    arsort($g_RegExpStat);
    
    foreach ($g_RegExpStat as $r => $v) {
        echo $v . "\t\t" . $r . "\n";
    }
    
    die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
    Quarantine();
}

if (isset($options['cmd'])) {
    stdOut("Run \"{$options['cmd']}\" ");
    system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($g_CriticalPHP);
$l_EC2 = count($g_CriticalJS) + count($g_Phishing) + count($g_WarningPHP[0]) + count($g_WarningPHP[1]);
$code  = 0;

if ($l_EC1 > 0) {
    $code = 2;
} else {
    if ($l_EC2 > 0) {
        $code = 1;
    }
}

$stat = array(
    'php_malware' => count($g_CriticalPHP),
    'js_malware' => count($g_CriticalJS),
    'phishing' => count($g_Phishing)
);

if (function_exists('aibolit_onComplete')) {
    aibolit_onComplete($code, $stat);
}

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine() {
    if (!file_exists(DOUBLECHECK_FILE)) {
        return;
    }
    
    $g_QuarantinePass = 'aibolit';
    
    $archive  = "AI-QUARANTINE-" . rand(100000, 999999) . ".zip";
    $infoFile = substr($archive, 0, -3) . "txt";
    $report   = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;
    
    
    foreach (file(DOUBLECHECK_FILE) as $file) {
        $file = trim($file);
        if (!is_file($file))
            continue;
        
        $lStat = stat($file);
        
        // skip files over 300KB
        if ($lStat['size'] > 300 * 1024)
            continue;
        
        // http://www.askapache.com/security/chmod-stat.html
        $p    = $lStat['mode'];
        $perm = '-';
        $perm .= (($p & 0x0100) ? 'r' : '-') . (($p & 0x0080) ? 'w' : '-');
        $perm .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
        $perm .= (($p & 0x0020) ? 'r' : '-') . (($p & 0x0010) ? 'w' : '-');
        $perm .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
        $perm .= (($p & 0x0004) ? 'r' : '-') . (($p & 0x0002) ? 'w' : '-');
        $perm .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));
        
        $owner = (function_exists('posix_getpwuid')) ? @posix_getpwuid($lStat['uid']) : array(
            'name' => $lStat['uid']
        );
        $group = (function_exists('posix_getgrgid')) ? @posix_getgrgid($lStat['gid']) : array(
            'name' => $lStat['uid']
        );
        
        $inf['permission'][] = $perm;
        $inf['owner'][]      = $owner['name'];
        $inf['group'][]      = $group['name'];
        $inf['size'][]       = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
        $inf['ctime'][]      = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
        $inf['mtime'][]      = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
        $files[]             = strpos($file, './') === 0 ? substr($file, 2) : $file;
    }
    
    // get config files for cleaning
    $configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
    $configFiles      = preg_grep("~$configFilesRegex~", $files);
    
    // get columns width
    $width = array();
    foreach (array_keys($inf) as $k) {
        $width[$k] = strlen($k);
        for ($i = 0; $i < count($inf[$k]); ++$i) {
            $len = strlen($inf[$k][$i]);
            if ($len > $width[$k])
                $width[$k] = $len;
        }
    }
    
    // headings of columns
    $info = '';
    foreach (array_keys($inf) as $k) {
        $info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT) . ' ';
    }
    $info .= "name\n";
    
    for ($i = 0; $i < count($files); ++$i) {
        foreach (array_keys($inf) as $k) {
            $info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT) . ' ';
        }
        $info .= $files[$i] . "\n";
    }
    unset($inf, $width);
    
    exec("zip -v 2>&1", $output, $code);
    
    if ($code == 0) {
        $filter = '';
        if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
            $filter = "|grep -v -E '$configFilesRegex'";
        }
        
        exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
        if ($code == 0) {
            file_put_contents($infoFile, $info);
            $m = array();
            if (!empty($filter)) {
                foreach ($configFiles as $file) {
                    $tmp  = file_get_contents($file);
                    // remove  passwords
                    $tmp  = preg_replace('~^.*?pass.*~im', '', $tmp);
                    // new file name
                    $file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
                    file_put_contents($file, $tmp);
                    $m[] = $file;
                }
            }
            
            exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
            stdOut("\nCreate archive '" . realpath($archive) . "'");
            stdOut("This archive have password '$g_QuarantinePass'");
            foreach ($m as $file)
                unlink($file);
            unlink($infoFile);
            return;
        }
    }
    
    $zip = new ZipArchive;
    
    if ($zip->open($archive, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === false) {
        stdOut("Cannot create '$archive'.");
        return;
    }
    
    foreach ($files as $file) {
        if (in_array($file, $configFiles)) {
            $tmp = file_get_contents($file);
            // remove  passwords
            $tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
            $zip->addFromString($file, $tmp);
        } else {
            $zip->addFile($file);
        }
    }
    $zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
    $zip->addFile($report, REPORT_FILE);
    $zip->addFromString($infoFile, $info);
    $zip->close();
    
    stdOut("\nCreate archive '" . realpath($archive) . "'.");
    stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    QCR_Debug('Check ' . $l_RootDir);
    
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type  = filetype($l_FileName);
            $l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && (!$l_IsDir)) {
                $g_UnixExec[] = $l_FileName;
                continue;
            }
            
            $l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);
            
            $l_NeedToScan = true;
            $l_Ext2       = substr(strstr(basename($l_FileName), '.'), 1);
            if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE)
                $l_NeedToScan = false;
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                $l_DirCounter++;
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_IntegrityCheck($l_FileName);
                
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    $g_Counter++;
                }
            }
            
            if (!$l_NeedToScan)
                continue;
            
            if (IMAKE) {
                write_integrity_db_file($l_FileName);
                continue;
            }
            
            // ICHECK
            // skip if known and not modified.
            if (icheck($l_FileName))
                continue;
            
            $l_Buffer .= getRelativePath($l_FileName);
            $l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
    if (($l_RootDir == ROOT_PATH)) {
        write_integrity_db_file();
    }
    
}


function getRelativePath($l_FileName) {
    return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}

/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    static $l_status = array('modified' => 'modified', 'added' => 'added');
    
    $l_RelativePath = getRelativePath($l_FileName);
    $l_known        = isset($g_IntegrityDB[$l_RelativePath]);
    
    if (is_dir($l_FileName)) {
        if ($l_known) {
            unset($g_IntegrityDB[$l_RelativePath]);
        } else {
            $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        }
        return $l_known;
    }
    
    if ($l_known == false) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        return false;
    }
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    if ($g_IntegrityDB[$l_RelativePath] != $hash) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
        return false;
    }
    
    unset($g_IntegrityDB[$l_RelativePath]);
    return true;
}

function write_integrity_db_file($l_FileName = '') {
    static $l_Buffer = '';
    
    if (empty($l_FileName)) {
        empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
        return;
    }
    
    $l_RelativePath = getRelativePath($l_FileName);
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    $l_Buffer .= "$l_RelativePath|$hash\n";
    
    if (strlen($l_Buffer) > 32000) {
        file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
    }
}

function load_integrity_db() {
    global $g_IntegrityDB;
    file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);
    
    $s_file = new SplFileObject('compress.zlib://' . INTEGRITY_DB_FILE);
    $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
    
    foreach ($s_file as $line) {
        $i = strrpos($line, '|');
        if (!$i)
            continue;
        $g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i + 1);
    }
    
    $s_file = null;
}


function getStdin()
{
    $stdin  = '';
    $f      = @fopen('php://stdin', 'r');
    while($line = fgets($f)) 
    {
        $stdin .= $line;
    }
    fclose($f);
    return $stdin;
}

function OptimizeSignatures() {
    global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
    global $g_JSVirSig, $gX_JSVirSig;
    global $g_AdwareSig;
    global $g_PhishingSig;
    global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;
    
    (AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
    (AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
    $gX_FlexDBShe = $gXX_FlexDBShe = array();
    
    (AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
    $gX_JSVirSig = array();
    
    $count = count($g_FlexDBShe);
    
    for ($i = 0; $i < $count; $i++) {
        if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
            $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
        if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
            $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
        if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
            $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';
        
        $g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);
        
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
    }
    
    optSig($g_FlexDBShe);
    
    optSig($g_JSVirSig);
    optSig($g_AdwareSig);
    optSig($g_PhishingSig);
    optSig($g_SusDB);
    //optSig($g_SusDBPrio);
    //optSig($g_ExceptFlex);
    
    // convert exception rules
    $cnt = count($g_ExceptFlex);
    for ($i = 0; $i < $cnt; $i++) {
        $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
        if (!strlen($g_ExceptFlex[$i]))
            unset($g_ExceptFlex[$i]);
    }
    
    $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs) {
    $sigs = array_unique($sigs);
    
    // Add SigId
    foreach ($sigs as &$s) {
        $s .= '(?<X' . myCheckSum($s) . '>)';
    }
    unset($s);
    
    $fix = array(
        '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
        'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
        '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
        '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
    );
    
    $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
    
    $fix = array(
        '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
        '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
    );
    
    $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);
    
    optSigCheck($sigs);
    
    $tmp = array();
    foreach ($sigs as $i => $s) {
        if (!preg_match('#^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$#', $s)) {
            unset($sigs[$i]);
            $tmp[] = $s;
        }
    }
    
    usort($sigs, 'strcasecmp');
    $txt = implode("\n", $sigs);
    
    for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
        $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
    }
    
    $sigs = array_merge(explode("\n", $txt), $tmp);
    
    optSigCheck($sigs);
}

function optMergePrefixes($m) {
    $limit = 8000;
    
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $len = $prefix_len;
    $r   = array();
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        
        if (strlen($line) > $limit) {
            $r[] = $line;
            continue;
        }
        
        $s = substr($line, $prefix_len);
        $len += strlen($s);
        if ($len > $limit) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
            $suffixes = array();
            $len      = $prefix_len + strlen($s);
        }
        $suffixes[] = $s;
    }
    
    if (!empty($suffixes)) {
        if (count($suffixes) == 1) {
            $r[] = $prefix . $suffixes[0];
        } else {
            $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
        }
    }
    
    return implode("\n", $r);
}

function optMergePrefixes_Old($m) {
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        $suffixes[] = substr($line, $prefix_len);
    }
    
    return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs) {
    $result = true;
    
    foreach ($sigs as $k => $sig) {
        if (trim($sig) == "") {
            if (DEBUG_MODE) {
                echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
        
        if (@preg_match('#' . $sig . '#smiS', '') === false) {
            $error = error_get_last();
            if (DEBUG_MODE) {
                echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
    }
    
    return $result;
}

function _hash_($text) {
    static $r;
    
    if (empty($r)) {
        for ($i = 0; $i < 256; $i++) {
            if ($i < 33 OR $i > 127)
                $r[chr($i)] = '';
        }
    }
    
    return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) {
    global $defaults;

    if (empty($list))
        return array();
    
    $file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';
    if (isset($defaults['avdb'])) {
       $file = dirname($defaults['avdb']) . '/AIBOLIT-WHITELIST.db';
    }

    if (!file_exists($file)) {
        return array();
    }
    
    $snum = max(0, @filesize($file) - 1024) / 20;
    stdOut("\nLoaded " . ceil($snum) . " known files from " . $file . "\n");
    
    sort($list);
    
    $hash = reset($list);
    
    $fp = @fopen($file, 'rb');
    
    if (false === $fp)
        return array();
    
    $header = unpack('V256', fread($fp, 1024));
    
    $result = array();
    
    foreach ($header as $chunk_id => $chunk_size) {
        if ($chunk_size > 0) {
            $str = fread($fp, $chunk_size);
            
            do {
                $raw = pack("H*", $hash);
                $id  = ord($raw[0]) + 1;
                
                if ($chunk_id == $id AND binarySearch($str, $raw)) {
                    $result[] = $hash;
                }
                
            } while ($chunk_id >= $id AND $hash = next($list));
            
            if ($hash === false)
                break;
        }
    }
    
    fclose($fp);
    
    return $result;
}


function binarySearch($str, $item) {
    $item_size = strlen($item);
    if ($item_size == 0)
        return false;
    
    $first = 0;
    
    $last = floor(strlen($str) / $item_size);
    
    while ($first < $last) {
        $mid = $first + (($last - $first) >> 1);
        $b   = substr($str, $mid * $item_size, $item_size);
        if (strcmp($item, $b) <= 0)
            $last = $mid;
        else
            $first = $mid + 1;
    }
    
    $b = substr($str, $last * $item_size, $item_size);
    if ($b == $item) {
        return true;
    } else {
        return false;
    }
}

function getSigId($l_Found) {
    foreach ($l_Found as $key => &$v) {
        if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
            return substr($key, 1);
        }
    }
    
    return null;
}

function die2($str) {
    if (function_exists('aibolit_onFatalError')) {
        aibolit_onFatalError($str);
    }
    die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
    global $g_DeMapper;
    
    if ($l_DeobfType != '') {
        if (DEBUG_MODE) {
            stdOut("\n-----------------------------------------------------------------------------\n");
            stdOut("[DEBUG]" . $l_Filename . "\n");
            var_dump(getFragment($l_Unwrapped, $l_Pos));
            stdOut("\n...... $l_DeobfType ...........\n");
            var_dump($l_Unwrapped);
            stdOut("\n");
        }
        
        switch ($l_DeobfType) {
            case '_GLOBALS_':
                foreach ($g_DeMapper as $fkey => $fvalue) {
                    if (DEBUG_MODE) {
                        stdOut("[$fkey] => [$fvalue]\n");
                    }
                    
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        if (DEBUG_MODE) {
                            stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                        }
                        
                        return true;
                    }
                }
                break;
        }
        
        
        return false;
    }
}

$full_code = '';

function deobfuscate_bitrix($str) {
    $res      = $str;
    $funclist = array();
    $strlist  = array();
    $res      = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
    $res      = preg_replace_callback('~(?:min|max)\(\s*\d+[\,\|\s\|+\|\-\|\*\|\/][\d\s\.\,\+\-\*\/]+\)~ms', "calc", $res);
    $res = preg_replace_callback('|(round\((.+?)\))|smi', function($matches) {
        return round($matches[2]);
    }, $res);
    $res = preg_replace_callback('|base64_decode\(["\'](.*?)["\']\)|smi', function($matches) {
        return "'" . base64_decode($matches[1]) . "'";
    }, $res);
    
    $res = preg_replace_callback('|["\'](.*?)["\']|sm', function($matches) {
        $temp = base64_decode($matches[1]);
        if (base64_encode($temp) === $matches[1] && preg_match('#^[ -~]*$#', $temp)) {
            return "'" . $temp . "'";
        } else {
            return "'" . $matches[1] . "'";
        }
    }, $res);
    
    
    if (preg_match_all('|\$GLOBALS\[\'(.+?)\'\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $varname            = $found[1];
            $funclist[$varname] = explode(',', $found[2]);
            $funclist[$varname] = array_map(function($value) {
                return trim($value, "'");
            }, $funclist[$varname]);
            
            $res = preg_replace_callback('|\$GLOBALS\[\'' . $varname . '\'\]\[(\d+)\]|smi', function($matches) use ($varname, $funclist) {
                return $funclist[$varname][$matches[1]];
            }, $res);
        }
    }
    
    
    if (preg_match_all('|function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);[^}]+}|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode(',', $found[2]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|smi', function($matches) use ($strlist) {
                return $strlist[$matches[1]];
            }, $res);
            
            //$res = preg_replace('~' . quotemeta(str_replace('~', '\\~', $found[0])) . '~smi', '', $res);
        }
    }
    
    $res = preg_replace('~<\?(php)?\s*\?>~smi', '', $res);
    if (preg_match_all('~<\?\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3=array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode("',", $found[5]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|sm', function($matches) use ($strlist) {
                return $strlist[$matches[1]] . "'";
            }, $res);
            
        }
    }
    
    return $res;
}

function calc($expr) {
    if (is_array($expr))
        $expr = $expr[0];
    preg_match('~(min|max)?\(([^\)]+)\)~msi', $expr, $expr_arr);
    if ($expr_arr[1] == 'min' || $expr_arr[1] == 'max')
        return $expr_arr[1](explode(',', $expr_arr[2]));
    else {
        preg_match_all('~([\d\.]+)([\*\/\-\+])?~', $expr, $expr_arr);
        if (in_array('*', $expr_arr[2]) !== false) {
            $pos  = array_search('*', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "*" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('/', $expr_arr[2]) !== false) {
            $pos  = array_search('/', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "/" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('-', $expr_arr[2]) !== false) {
            $pos  = array_search('-', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "-" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('+', $expr_arr[2]) !== false) {
            $pos  = array_search('+', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "+" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } else {
            return $expr;
        }
        
        return $expr;
    }
}

function my_eval($matches) {
    $string = $matches[0];
    $string = substr($string, 5, strlen($string) - 7);
    return decode($string);
}

function decode($string, $level = 0) {
    if (trim($string) == '')
        return '';
    if ($level > 100)
        return '';
    
    if (($string[0] == '\'') || ($string[0] == '"')) {
        return substr($string, 1, strlen($string) - 2); //
    } elseif ($string[0] == '$') {
        global $full_code;
        $string = str_replace(")", "", $string);
        preg_match_all('~\\' . $string . '\s*=\s*(\'|")([^"\']+)(\'|")~msi', $full_code, $matches);
        return $matches[2][0]; //
    } else {
        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
        
        $arg = decode(substr($string, $pos + 1), $level + 1);
        if (strtolower($function) == 'base64_decode')
            return @base64_decode($arg);
        else if (strtolower($function) == 'gzinflate')
            return @gzinflate($arg);
        else if (strtolower($function) == 'gzuncompress')
            return @gzuncompress($arg);
        else if (strtolower($function) == 'strrev')
            return @strrev($arg);
        else if (strtolower($function) == 'str_rot13')
            return @str_rot13($arg);
        else
            return $arg;
    }
}

function deobfuscate_eval($str) {
    global $full_code;
    $res = preg_replace_callback('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress).*?\);~msi', "my_eval", $str);
    return str_replace($str, $res, $full_code);
}

function getEvalCode($string) {
    preg_match("/eval\((.*?)\);/", $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}

function getTextInsideQuotes($string) {
    if (preg_match_all('/("(.*?)")/', $string, $matches))
        return @end(end($matches));
    elseif (preg_match_all('/(\'(.*?)\')/', $string, $matches))
        return @end(end($matches));
    else
        return '';
}

function deobfuscate_lockit($str) {
    $obfPHP        = $str;
    $phpcode       = base64_decode(getTextInsideQuotes(getEvalCode($obfPHP)));
    $hexvalues     = getHexValues($phpcode);
    $tmp_point     = getHexValues($obfPHP);
    $pointer1      = hexdec($tmp_point[0]);
    $pointer2      = hexdec($hexvalues[0]);
    $pointer3      = hexdec($hexvalues[1]);
    $needles       = getNeedles($phpcode);
    $needle        = $needles[count($needles) - 2];
    $before_needle = end($needles);
    
    
    $phpcode = base64_decode(strtr(substr($obfPHP, $pointer2 + $pointer3, $pointer1), $needle, $before_needle));
    return "<?php {$phpcode} ?>";
}


function getNeedles($string) {
    preg_match_all("/'(.*?)'/", $string, $matches);
    
    return (empty($matches)) ? array() : $matches[1];
}

function getHexValues($string) {
    preg_match_all('/0x[a-fA-F0-9]{1,8}/', $string, $matches);
    return (empty($matches)) ? array() : $matches[0];
}

function deobfuscate_als($str) {
    preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str, $layer1);
    preg_match('~\$[O0]+=(\$[O0]+\()+\$[O0]+,[0-9a-fx]+\),\'([^\']+)\',\'([^\']+)\'\)\);eval\(~msi', base64_decode($layer1[1]), $layer2);
    $res = explode("?>", $str);
    if (strlen(end($res)) > 0) {
        $res = substr(end($res), 380);
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
    }
    return "<?php {$res} ?>";
}

function deobfuscate_byterun($str) {
    global $full_code;
    preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
    $res = base64_decode($matches[1]);
    $res = strtr($res, '123456aouie', 'aouie123456');
    return "<?php " . str_replace($matches[0], $res, $full_code) . " ?>";
}

function deobfuscate_urldecode($str) {
    preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str, $matches);
    $alph  = urldecode($matches[2]);
    $funcs = $matches[3];
    for ($i = 0; $i < strlen($alph); $i++) {
        $funcs = str_replace($matches[1] . '{' . $i . '}.', $alph[$i], $funcs);
        $funcs = str_replace($matches[1] . '{' . $i . '}', $alph[$i], $funcs);
    }
    
    $str   = str_replace($matches[3], $funcs, $str);
    $funcs = explode(';', $funcs);
    foreach ($funcs as $func) {
        $func_arr = explode("=", $func);
        if (count($func_arr) == 2) {
            $func_arr[0] = str_replace('$', '', $func_arr[0]);
            $str         = str_replace('${"GLOBALS"}["' . $func_arr[0] . '"]', $func_arr[1], $str);
        }
    }
    
    return $str;
}


function formatPHP($string) {
    $string = str_replace('<?php', '', $string);
    $string = str_replace('?>', '', $string);
    $string = str_replace(PHP_EOL, "", $string);
    $string = str_replace(";", ";\n", $string);
    return $string;
}

function deobfuscate_fopo($str) {
    $phpcode = formatPHP($str);
    $phpcode = base64_decode(getTextInsideQuotes(getEvalCode($phpcode)));
    @$phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(end(explode(':', $phpcode))))));
    $old = '';
    while (($old != $phpcode) && (strlen(strstr($phpcode, '@eval($')) > 0)) {
        $old   = $phpcode;
        $funcs = explode(';', $phpcode);
        if (count($funcs) == 5)
            $phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(getEvalCode($phpcode)))));
        else if (count($funcs) == 4)
            $phpcode = gzinflate(base64_decode(getTextInsideQuotes(getEvalCode($phpcode))));
    }
    
    return substr($phpcode, 2);
}

function getObfuscateType($str) {
	$str = str_replace([".''","''.",'.""','"".'],"",$str);

    if (preg_match('~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~function\s*_+\d+\s*\(\s*\$i\s*\)\s*{\s*\$a\s*=\s*Array~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str))
        return "ALS-Fullsite";
    if (preg_match('~\$[O0]*=urldecode\(\'%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64\'\);\s*\$GLOBALS\[\'[O0]*\'\]=\$[O0]*~msi', $str))
        return "LockIt!";
    if (preg_match('~\$\w+="(\\\x?[0-9a-f]+){13}";@eval\(\$\w+\(~msi', $str))
        return "FOPO";
    if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms', $str))
        return "ByteRun";
    if (preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str))
        return "urldecode_globals";
    if (preg_match('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress)~msi', $str))
        return "eval";
}

function deobfuscate($str) {
	global $full_code;
	$str = str_replace([".''","''.",'.""','"".'],"",$str);
	$full_code = $str;

    switch (getObfuscateType($str)) {
        case '_GLOBALS_':
            $str = deobfuscate_bitrix(($str));
            break;
        case 'eval':
            $str = deobfuscate_eval(($str));
            break;
        case 'ALS-Fullsite':
            $str = deobfuscate_als(($str));
            break;
        case 'LockIt!':
            $str = deobfuscate_lockit($str);
            break;
        case 'FOPO':
            $str = deobfuscate_fopo(($str));
            break;
        case 'ByteRun':
            $str = deobfuscate_byterun(($str));
            break;
        case 'urldecode_globals':
            $str = deobfuscate_urldecode(($str));
            break;
    }
    
    return $str;
}

function convertToUTF8($text)
{
    if (function_exists('mb_convert_encoding')) {
       $text = @mb_convert_encoding($text, 'utf-8', 'auto');
       $text = @mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    }

    return $text;
}
