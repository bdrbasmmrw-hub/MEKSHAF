<?php
declare(strict_types=1);

require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

// جلب أحدث السجلات (للشريط الحي)
if ($method === 'GET' && isset($_GET['action']) && $_GET['action'] === 'feed') {
    $db = getDB();
    if (!$db) {
        respond(['status' => 'success', 'reports' => []]);
    }
    $stmt = $db->query("SELECT scam_text, verdict, percentage, created_at FROM reports ORDER BY id DESC LIMIT 5");
    respond(['status' => 'success', 'reports' => $stmt->fetchAll()]);
}

if ($method === 'POST' && strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    $input = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($input)) {
        respond(['status' => 'error', 'message' => 'البيانات المرسلة غير صالحة.'], 400);
    }

    $text = trim((string) ($input['text'] ?? ''));
    if ($text === '') {
        respond(['status' => 'error', 'message' => 'من فضلك أدخل نصاً أو رابطاً للفحص.'], 422);
    }
    if (mb_strlen($text) > MAX_INPUT_LENGTH) {
        respond(['status' => 'error', 'message' => 'النص طويل جداً (الحد الأقصى ' . MAX_INPUT_LENGTH . ' حرف).'], 413);
    }

    $score         = 0;
    $reasons       = [];
    $officialCount = 0;

    foreach (extractHosts($text) as $h) {
        $host = $h['host'];

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $score += 30;
            addReason($reasons, 'risk', "الرابط يستخدم عنوان IP مباشر ($host) بدل اسم موقع، وده شائع في النصب.");
            continue;
        }

        if (isOfficial($host)) {
            $officialCount++;
            addReason($reasons, 'info', "الرابط ($host) ينتمي لموقع رسمي معروف.");
            continue;
        }

        $norm  = leetNormalize($host);
        $label = leetNormalize(mainLabel($host));
        $spoofOf = null;

        foreach (BRANDS as $brand => $domains) {
            if (strlen($brand) < 5) {
                continue;
            }
            $threshold = strlen($brand) >= 8 ? 2 : 1;
            if (strpos($norm, $brand) !== false
                || (strlen($label) <= 40 && ($d = levenshtein($label, $brand)) > 0 && $d <= $threshold)) {
                $spoofOf = $domains[0];
                break;
            }
        }

        if ($spoofOf !== null) {
            $score += 90;
            addReason($reasons, 'risk', "الرابط ($host) يحاول تقليد الموقع الرسمي ($spoofOf).");
        } else {
            addReason($reasons, 'info', "الرابط ($host) مش في قائمة المواقع الموثوقة (ده مش معناه إنه خطر بالضرورة).");
        }

        if ($h['hasUser']) {
            $score += 30;
            addReason($reasons, 'risk', "الرابط ($host) فيه علامة @ لإخفاء الوجهة الحقيقية.");
        }
        if (in_array($host, SHORTENERS, true)) {
            $score += 25;
            addReason($reasons, 'risk', "الرابط مختصر ($host) ومينفعش تعرف وجهته الحقيقية.");
        }
        $tld = substr(strrchr($host, '.') ?: '', 1);
        if (in_array($tld, SUSPICIOUS_TLDS, true)) {
            $score += 20;
            addReason($reasons, 'risk', "امتداد النطاق (.$tld) كتير بيتستخدم في المواقع المشبوهة.");
        }
        if (strpos($host, 'xn--') !== false) {
            $score += 40;
            addReason($reasons, 'risk', "النطاق ($host) بيستخدم حروف مموهة (Punycode) لتقليد موقع تاني.");
        }
        if (substr_count($host, '-') >= 3) {
            $score += 15;
            addReason($reasons, 'risk', "اسم النطاق ($host) فيه شُرَط كتير وده مؤشر مشبوه.");
        }
        if ($h['plainHttp']) {
            $score += 10;
            addReason($reasons, 'risk', "الرابط ($host) غير مشفّر (http بدل https).");
        }
    }

    $normText = normalizeArabic($text);
    $matched  = [];
    foreach (scamRules() as [$regex, $weight, $label]) {
        if (preg_match($regex, $normText)) {
            $score    += $weight;
            $matched[] = $label;
        }
    }

    $triggerKeywords = [
        'فلوس', 'جنيه', 'دولار', 'ريال', 'درهم', 'بنك', 'بنوك', 'فيزا', 'ماستر كارد', 
        'رصيد', 'شحن', 'كارت', 'محفظة', 'فودافون كاش', 'انستا باي', 'حسابك البنكي',
        'مبروك', 'كسبت', 'ربحت', 'جايزة', 'مكسب', 'هدايا', 'سحب', 'مسابقة'
    ];
    
    $triggerCount = 0;
    foreach ($triggerKeywords as $kw) {
        if (strpos($normText, $kw) !== false) {
            $triggerCount++;
        }
    }

    if ($triggerCount > 0) {
        $score += ($triggerCount * 10);
    }

    if ($matched) {
        addReason($reasons, 'risk', 'النص يحتوي على عبارات احتيالية محتملة: (' . implode('، ', array_unique($matched)) . ').');
    }

    $score = min(100, $score);

    if ($triggerCount >= 2 && $score < 45) {
        $score = rand(45, 55); 
    }

    if ($score >= 70) {
        $level = 'danger';  $verdict = 'خطر عالٍ - غالباً محاولة نصب!';
    } elseif ($score >= 30) {
        $level = 'warning'; $verdict = 'محتوى مشكوك فيه - توخَّ الحذر';
    } else {
        $level   = 'safe';
        $verdict = ($officialCount > 0 && $score === 0) ? 'الرابط رسمي ولم نرصد مؤشرات خطر' : 'لم نرصد مؤشرات خطر معروفة';
    }

    if ($level === 'safe') {
        addReason($reasons, 'info', 'الفحص بيعتمد على قواعد معروفة ومش بيضمن الأمان 100%. متشاركش أبداً كود OTP أو الرقم السري مع أي حد.');
    }

    // تخزين السجل بلا إسم في قاعدة البيانات
    $db = getDB();
    if ($db) {
        $stmt = $db->prepare("INSERT INTO reports (scam_text, verdict, percentage) VALUES (?, ?, ?)");
        $stmt->execute([mb_substr($text, 0, 100), $verdict, $score]);
    }

    respond([
        'status'     => 'success',
        'percentage' => $score,
        'verdict'    => $verdict,
        'level'      => $level,
        'reasons'    => $reasons,
    ]);
}