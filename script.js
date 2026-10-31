const $ = (id) => document.getElementById(id);
const SCAN_LABEL = '<i class="fa-solid fa-magnifying-glass"></i> افحص دلوقتي';

function showError(msg) {
    const box = $('errorBox');
    box.textContent = msg;
    box.style.display = 'block';
    $('resultCard').style.display = 'none';
}

function loadExample(type) {
    const examples = {
        vodafone: "مبروك كسبت 1000 جنيه رصيد مجاني من فودافون كاش! دوس على الرابط ده عشان تستلم جائزتك: http://vodafone-gift-eg.xyz",
        bank: "تنبيه من البنك الأهلي: تم إيقاف حسابك البنكي مؤقتاً لتحديث البيانات، برجاء الاتصال بـ 0123456789 أو الدخول لتأكيد رقْم الكود السرى OTP",
        safe: "أهلاً بكم، فضلاً راجع جدول المحاضرات غداً في الكلية الساعة 9 صباحاً بالتوفيق."
    };
    $('inputText').value = examples[type] || '';
    $('charCount').textContent = $('inputText').value.length;
}

const BRANDS = {
    'facebook': ['facebook.com', 'fb.com', 'facebookmail.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com', 'whatsapp.net'],
    'google': ['google.com', 'google.com.eg', 'googleapis.com', 'googleusercontent.com'],
    'paypal': ['paypal.com'],
    'vodafone': ['vodafone.com.eg', 'vodafone.com'],
    'banquemisr': ['banquemisr.com'],
    'nbe': ['nbe.com.eg'],
    'fawry': ['fawry.com'],
    'instapay': ['instapay.eg']
};

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc'];
const SUSPICIOUS_TLDS = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'work', 'icu', 'buzz', 'rest'];

function levenshtein(a, b) {
    const tmp = [];
    for (let i = 0; i <= a.length; i++) tmp[i] = [i];
    for (let j = 0; j <= b.length; j++) tmp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            tmp[i][j] = Math.min(
                tmp[i - 1][j] + 1,
                tmp[i][j - 1] + 1,
                tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
            );
        }
    }
    return tmp[a.length][b.length];
}

function leetNormalize(s) {
    return s.toLowerCase()
        .replace(/[013457$@]/g, c => ({'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','$':'s','@':'a'}[c]))
        .replace(/(rn|vv)/g, m => m === 'rn' ? 'm' : 'w');
}

function mainLabel(host) {
    const labels = host.split('.');
    if (labels.length < 2) return host;
    let tld = labels.pop();
    if (labels.length >= 2 && tld.length === 2 && ['com', 'org', 'net', 'co', 'gov', 'edu', 'ac'].includes(labels[labels.length - 1])) {
        labels.pop();
    }
    return labels[labels.length - 1] || host;
}

function isOfficial(host) {
    for (const domains of Object.values(BRANDS)) {
        for (const d of domains) {
            if (host === d || host.endsWith('.' + d)) return true;
        }
    }
    return false;
}

function normalizeArabic(s) {
    return s.toLowerCase()
        .normalize("NFKD").replace(/[\u064B-\u065F\u0670\u0640]/g, '')
        .replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'y')
        .replace(/[٠-٩]/g, d => '0123456789'[d.charCodeAt(0) - 1632])
        .replace(/\s+/g, ' ').trim();
}

function analyzeText() {
    const textInput = $('inputText').value.trim();
    const btn = $('scanBtn');
    const scanner = $('scannerLine');
    const errorBox = $('errorBox');

    errorBox.style.display = 'none';

    if (!textInput) {
        showError('من فضلك ادخل نصاً أو رابطاً أولاً!');
        return;
    }

    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> جاري الفحص الذكي...';
    btn.disabled = true;
    scanner.style.display = 'block';

    setTimeout(() => {
        let score = 0;
        const reasons = [];
        let officialCount = 0;

        const urlRegex = /(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;
        const potentialUrls = textInput.match(urlRegex) || [];

        potentialUrls.forEach(rawUrl => {
            try {
                let cleanUrl = rawUrl.toLowerCase();
                let plainHttp = cleanUrl.startsWith('http://');
                let host = cleanUrl.replace(/^https?:\/\//, '').split('/')[0].split('?')[0].split(':')[0];

                if (isOfficial(host)) {
                    officialCount++;
                    reasons.push({type: 'info', text: `الرابط (${host}) ينتمي لموقع رسمي معروف.`});
                    return;
                }

                const norm = leetNormalize(host);
                const label = leetNormalize(mainLabel(host));
                let spoofOf = null;

                for (const [brand, domains] of Object.entries(BRANDS)) {
                    if (brand.length < 5) continue;
                    let threshold = brand.length >= 8 ? 2 : 1;
                    let d = levenshtein(label, brand);
                    if (norm.includes(brand) || (label.length <= 40 && d > 0 && d <= threshold)) {
                        spoofOf = domains[0];
                        break;
                    }
                }

                if (spoofOf) {
                    score += 90;
                    reasons.push({type: 'risk', text: `الرابط (${host}) يحاول تقليد الموقع الرسمي (${spoofOf}).`});
                }

                if (SHORTENERS.includes(host)) {
                    score += 25;
                    reasons.push({type: 'risk', text: `الرابط مختصر (${host}) ويخفي وجهته.`});
                }
                const tld = host.split('.').pop();
                if (SUSPICIOUS_TLDS.includes(tld)) {
                    score += 20;
                    reasons.push({type: 'risk', text: `امتداد النطاق (.${tld}) مشبوه.`});
                }
                if (host.includes('xn--')) {
                    score += 40;
                    reasons.push({type: 'risk', text: `النطاق يستخدم حروف مموهة (Punycode).`});
                }
                if ((host.match(/-/g) || []).length >= 3) {
                    score += 15;
                    reasons.push({type: 'risk', text: `اسم النطاق يحتوي على شرطات كثيرة.`});
                }
                if (plainHttp) {
                    score += 10;
                    reasons.push({type: 'risk', text: `الرابط غير مشفّر (http غير آمن).`});
                }
            } catch (e) {}
        });

        const triggerKeywords = [
            'فلوس', 'جنيه', 'دولار', 'ريال', 'درهم', 'بنك', 'بنوك', 'فيزا', 'ماستر كارد', 
            'رصيد', 'شحن', 'كارت', 'محفظة', 'فودافون كاش', 'انستا باي', 'حسابك البنكي',
            'مبروك', 'کسبت', 'ربحت', 'جايزة', 'مكسب', 'هدايا', 'سحب', 'مسابقة',
            'تحديث','OTP', 'كود', 'باسورد', 'سري' , 'تأكيد', 'تفعيل', 'تسجيل الدخول', 'الدخول للحساب', 'التحقق من الحساب', 'التحقق من الهوية'
            , 'تأكيد الهوية', 'تأكيد الحساب', 'تأكيد الدخول', 'تأكيد تسجيل الدخول', 'تأكيد كلمة المرور', 'تأكيد كلمة السر', 'تأكيد الرقم السري', 'تأكيد الرقم السري الخاص بك'
            , 'تالت ارقام في ضطر الفيزا' , 'ثلاثة ارقام خلف الفيزا' , 'ثلاثة ارقام في ظهر الفيزا'
        ];
        
        let normText = normalizeArabic(textInput);
        let triggerCount = 0;
        triggerKeywords.forEach(kw => {
            if (normText.includes(kw)) triggerCount++;
        });

        if (triggerCount > 0) score += (triggerCount * 10);
        if (triggerCount >= 2 && score < 45) score = Math.floor(Math.random() * (55 - 45 + 1)) + 45;

        score = Math.min(100, score);
        let level = 'safe';
        let verdict = 'لم نرصد مؤشرات خطر معروفة';

        if (score >= 70) {
            level = 'danger';
            verdict = 'خطر عالٍ - غالباً محاولة نصب!';
        } else if (score >= 30) {
            level = 'warning';
            verdict = 'محتوى مشكوك فيه - توخَّ الحذر';
        } else if (officialCount > 0) {
            verdict = 'الرابط رسمي ولم نرصد مؤشرات خطر';
        }

        if (level === 'safe') {
            reasons.push({type: 'info', text: 'الفحص محلي ولا يضمن الأمان 100%. لا تشارك كود OTP أو الرقم السري.'});
        }

        const card = $('resultCard');
        card.className = 'result-card ' + level;
        card.style.display = 'block';

        $('verdictTitle').textContent = verdict;
        $('scoreValue').textContent = score + '% نسبة الخطر';
        $('meterFill').style.width = '0';
        requestAnimationFrame(() => { $('meterFill').style.width = score + '%'; });

        const list = $('reasonsList');
        list.innerHTML = '';
        reasons.forEach((reason) => {
            const li = document.createElement('li');
            li.className = reason.type;
            const icon = document.createElement('i');
            icon.className = reason.type === 'risk' ? 'fa-solid fa-triangle-exclamation' : 'fa-solid fa-circle-info';
            const span = document.createElement('span');
            span.textContent = reason.text;
            li.append(icon, span);
            list.appendChild(li);
        });

        btn.innerHTML = SCAN_LABEL;
        btn.disabled = false;
        scanner.style.display = 'none';
    }, 600);
}

function shareReport() {
    const verdict = $('verdictTitle').textContent;
    const score = $('scoreValue').textContent;
    const shareText = `🛡️ نتيجة فحص منصة "MEKSHAF":\n📌 التقييم: ${verdict} (${score})\nاحذر ولا تشارك بياناتك السرية!`;
    navigator.clipboard.writeText(shareText).then(() => {
        alert('تم نسخ تقرير التحذير بنجاح!');
    });
}

const mockFeeds = [
    "MEKSHAF رصد بلاغ: رابط وهمي ينتحل صفة بنك شهير",
    "تحذير: رسالة احتيالية تعد برصيد مجاني",
    "تنبيه أمني: محاولة سرقة بيانات محفظة إلكترونية"
];
let feedIndex = 0;
setInterval(() => {
    feedIndex = (feedIndex + 1) % mockFeeds.length;
    $('feedText').textContent = mockFeeds[feedIndex];
}, 7000);

$('scanBtn').addEventListener('click', analyzeText);
$('clearBtn').addEventListener('click', () => {
    $('inputText').value = '';
    $('charCount').textContent = '0';
    $('resultCard').style.display = 'none';
    $('errorBox').style.display = 'none';
    $('inputText').focus();
});
$('inputText').addEventListener('input', (e) => { $('charCount').textContent = e.target.value.length; });
$('inputText').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyzeText();
});