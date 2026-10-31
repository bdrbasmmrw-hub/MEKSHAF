<?php
declare(strict_types=1);

/* =====================================================================
 *   MEKSHAF - ملف الإعدادات المحدث بقوائم الكلمات الموسعة
 * ===================================================================== */

const DB_HOST = 'localhost';
const DB_NAME = 'scam_detector';
const DB_USER = 'root';
const DB_PASS = '';

function getDB(): ?PDO {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        return $pdo;
    } catch (PDOException $e) {
        return null;
    }
}

const MAX_INPUT_LENGTH = 3000;
const MAX_HOSTS        = 10;

const BRANDS = [
    'facebook'   => ['facebook.com', 'fb.com', 'facebookmail.com'],
    'instagram'  => ['instagram.com'],
    'whatsapp'   => ['whatsapp.com', 'whatsapp.net'],
    'google'     => ['google.com', 'google.com.eg', 'googleapis.com', 'googleusercontent.com'],
    'paypal'     => ['paypal.com'],
    'vodafone'   => ['vodafone.com.eg', 'vodafone.com'],
    'banquemisr' => ['banquemisr.com'],
    'nbe'        => ['nbe.com.eg'],
    'fawry'      => ['fawry.com'],
    'instapay'   => ['instapay.eg'],
];

const SHORTENERS      = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc'];
const SUSPICIOUS_TLDS = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'work', 'icu', 'buzz', 'rest'];

function normalizeArabic(string $s): string
{
    $s = mb_strtolower($s, 'UTF-8');
    $s = preg_replace('/[\x{064B}-\x{065F}\x{0670}\x{0640}]/u', '', $s) ?? $s;
    $s = strtr($s, [
        'أ' => 'ا', 'إ' => 'ا', 'آ' => 'ا', 'ى' => 'ي', 'ة' => 'ه', 'ؤ' => 'و', 'ئ' => 'ي',
        '٠' => '0', '١' => '1', '٢' => '2', '٣' => '3', '٤' => '4',
        '٥' => '5', '٦' => '6', '٧' => '7', '٨' => '8', '٩' => '9',
    ]);
    return trim(preg_replace('/\s+/u', ' ', $s) ?? $s);
}

function phraseRegex(string $phrase): string
{
    return '/' . str_replace(' ', '\s+', preg_quote(normalizeArabic($phrase), '/')) . '/u';
}

function scamRules(): array
{
    // قاعدة بيانات ضخمة للعبارات المشبوهة بالعربي والإنجليزي
    $phrases = [
        // عبارات مصري وعربي
        'مبروك كسبت' => 35, 'مبروك ربحت' => 35, 'ابعت الرقم' => 30,
        'رقم الفيزا' => 45, 'الرقم السري' => 40, 'كلمة السر' => 40,
        'كود التفعيل' => 35, 'تحديث بيانات البنك' => 40, 'تحديث بياناتك' => 30,
        'تم ايقاف حسابك' => 35, 'حسابك هيتقفل' => 30, 'كارت شحن' => 25,
        'دوس هنا علشان تكسب' => 30, 'دوس هنا' => 20, 'اضغط على الرابط' => 20,
        'مبروك الجايزة' => 35, 'كسبت معانا' => 35, 'رصيد مجاني' => 30,
        'استلم هديتك' => 35, 'تم اختيارك' => 30, 'المحفظة الالكترونية' => 30,
        'تأكيد الحساب' => 35, 'تجميد الحساب' => 40, 'رقمك فاز' => 35,
        'اربح الان' => 30, 'جائزتك في انتظارك' => 30, 'الفرصة الاخيرة' => 25,
        'تحديث تطبيق البنك' => 35, 'كلمة المرور المؤقتة' => 40, 'ارسال الاموال' => 30,

        // عبارات إنجليزية (Phishing & Scams)
        'congratulations you won' => 40, 'claim your prize' => 35, 'urgent account verification' => 40,
        'your account has been suspended' => 45, 'update your banking details' => 40, 'verify your identity' => 35,
        'unauthorized login attempt' => 40, 'click here to unlock' => 30, 'enter your password' => 40,
        'confirm your credit card' => 45, 'suspected fraud activity' => 40, 'limited time offer' => 25,
        'exclusive reward waiting' => 30, 'amazon gift card reward' => 35, 'netflix subscription expired' => 35,
        'bank security alert' => 40, 'reset your credentials' => 35, 'verify your phone number' => 30,
        'your funds are on hold' => 40, 'immediate action required' => 30, 'security token required' => 40,
        'unlock your account' => 35, 'validate your email' => 30, 'strange login detected' => 35,
        'claim your stimulus package' => 30, 'free crypto giveaway' => 40, 'investment opportunity' => 30,
        'double your money' => 35, 'high returns guaranteed' => 35, 'customer support verification' => 35,
    ];

    $rules = [];
    foreach ($phrases as $p => $w) {
        $rules[] = [phraseRegex($p), $w, $p];
    }
    
    // قواعد عامة بالـ Regex للارقام والرموز
    $rules[] = ['/(?:ربح|كسب|won|winner)\w*\s*\d{3,}/u', 35, 'ربح/كسب مبلغ مالي أو جائزة'];
    $rules[] = ['/\b(?:otp|cvv|cvc|pin|password|passcode|passcode|secret code)\b/i', 45, 'طلب بيانات سرية أو كود تحقق (OTP/CVV)'];
    $rules[] = ['/(?:click here|اضغط هنا|دوس هنا)\s*(?:to|لـ)?\s*(?:verify|confirm|login|unlock|تأكيد|تحديث)/iu', 30, 'رابط مشبوه للحث على اتخاذ إجراء'];
    $rules[] = ['/(?:http|https):\/\/[^\s]+(?:free|prize|reward|gift|update|login|verify|bank|win)/i', 40, 'رابط خارجي يحتوي على كلمات جذب احتيالية'];
    
    return $rules;
}

function endsWith(string $haystack, string $suffix): bool
{
    return $suffix !== '' && substr($haystack, -strlen($suffix)) === $suffix;
}

function leetNormalize(string $s): string
{
    $s = strtr($s, ['0' => 'o', '1' => 'l', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '$' => 's', '@' => 'a']);
    return str_replace(['rn', 'vv'], ['m', 'w'], $s);
}

function mainLabel(string $host): string
{
    $labels = explode('.', $host);
    if (count($labels) < 2) {
        return $host;
    }
    $tld = array_pop($labels);
    if (count($labels) >= 2 && strlen($tld) === 2
        && in_array(end($labels), ['com', 'org', 'net', 'co', 'gov', 'edu', 'ac'], true)) {
        array_pop($labels);
    }
    return (string) end($labels);
}

function extractHosts(string $text): array
{
    $pattern = '~(?<![\w@.-])'
        . '((?:https?://(?:[^\s/@]+@)?)?'
        . '(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})'
        . '(?::\d+)?(?:[/?#][^\s]*)?)~iu';

    preg_match_all($pattern, $text, $m);
    $hosts = [];
    foreach ($m[1] ?? [] as $raw) {
        $raw       = rtrim($raw, '.,;:!?)]}»"\'،؟');
        $hasScheme = (bool) preg_match('~^https?://~i', $raw);
        $parts     = parse_url($hasScheme ? $raw : 'http://' . $raw);
        $host      = strtolower($parts['host'] ?? '');
        if ($host === '' || strlen($host) > 253) {
            continue;
        }
        $hosts[$host] = [
            'host'     => $host,
            'plainHttp'=> $hasScheme && stripos($raw, 'http://') === 0,
            'hasUser'  => $hasScheme && isset($parts['user']),
        ];
        if (count($hosts) >= MAX_HOSTS) {
            break;
        }
    }
    return array_values($hosts);
}

function isOfficial(string $host): bool
{
    foreach (BRANDS as $domains) {
        foreach ($domains as $d) {
            if ($host === $d || endsWith($host, '.' . $d)) {
                return true;
            }
        }
    }
    return false;
}

function addReason(array &$reasons, string $type, string $text): void
{
    $reasons[] = ['type' => $type, 'text' => $text];
}

function respond(array $data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// قائمة الكلمات الدلالية المحفزة الموسعة (عربي وإنجليزي)
function getTriggerKeywords(): array {
    return [
        // مصطلحات مصرية وعربية
        'فلوس', 'جنيه', 'دولار', 'ريال', 'درهم', 'بنك', 'بنوك', 'فيزا', 'ماستر كارد', 
        'رصيد', 'شحن', 'كارت', 'محفظة', 'فودافون كاش', 'انستا باي', 'حسابك البنكي',
        'مبروك', 'كسبت', 'ربحت', 'جايزة', 'مكسب', 'هدايا', 'سحب', 'مسابقة',
        'تفعيل', 'ايقاف', 'حظر', 'بيانات', 'سري', 'رقم سري', 'كود', 'تحويل',
        'محفظة ذكية', 'دعم فني', 'تحديث', 'توثيق', 'ارباح', 'استثمار', 'مجاناً',
        
        // مصطلحات إنجليزية (English Keywords)
        'money', 'cash', 'dollar', 'usd', 'bank', 'banking', 'visa', 'mastercard', 
        'credit card', 'debit card', 'account', 'balance', 'wallet', 'crypto', 
        'bitcoin', 'ethereum', 'usdt', 'investment', 'invest', 'profit', 'returns',
        'congratulations', 'winner', 'win', 'won', 'prize', 'gift', 'reward', 
        'free', 'giveaway', 'bonus', 'lucky', 'draw', 'sweepstakes',
        'urgent', 'emergency', 'alert', 'security', 'suspended', 'locked', 
        'blocked', 'verify', 'verification', 'validate', 'confirm', 'update', 
        'password', 'passcode', 'pin', 'otp', 'cvv', 'login', 'signin', 'access',
        'claim', 'expire', 'limited', 'offer', 'support', 'helpdesk', 'update data',
    ];
}