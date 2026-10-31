const $ = (id) => document.getElementById(id);
const SCAN_LABEL = '<i class="fa-solid fa-magnifying-glass"></i> افحص دلوقتي';

function showError(msg) {
    const box = $('errorBox');
    box.textContent = msg;
    box.style.display = 'block';
    $('resultCard').style.display = 'none';
}

// أمثلة سريعة للتجربة بضغطة زر
function loadExample(type) {
    const examples = {
        vodafone: "مبروك كسبت 1000 جنيه رصيد مجاني من فودافون كاش! دوس على الرابط ده عشان تستلم جائزتك: http://vodafone-gift-eg.xyz",
        bank: "تنبيه من البنك الأهلي: تم إيقاف حسابك البنكي مؤقتاً لتحديث البيانات، برجاء الاتصال بـ 0123456789 أو الدخول لتأكيد رقْم الكود السرى OTP",
        safe: "أهلاً بكم، فضلاً راجع جدول المحاضرات غداً في الكلية الساعة 9 صباحاً بالتوفيق."
    };
    $('inputText').value = examples[type] || '';
    $('charCount').textContent = $('inputText').value.length;
}

async function analyzeText() {
    const textInput = $('inputText').value.trim();
    const btn = $('scanBtn');
    const scanner = $('scannerLine');

    $('errorBox').style.display = 'none';

    if (!textInput) {
        showError('من فضلك ادخل نصاً أو رابطاً أولاً!');
        return;
    }

    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> جاري فحص الذكاء الاصطناعي...';
    btn.disabled = true;
    scanner.style.display = 'block'; // تفعيل مؤشر الليزر

    try {
        const response = await fetch('api.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: textInput })
        });

        let data = await response.json();

        if (data.status !== 'success') {
            showError(data.message || 'حدث خطأ غير متوقع.');
            return;
        }

        const card = $('resultCard');
        card.className = 'result-card ' + data.level;
        card.style.display = 'block';

        $('verdictTitle').textContent = data.verdict;
        $('scoreValue').textContent = data.percentage + '% نسبة الخطر';
        $('meterFill').style.width = '0';
        requestAnimationFrame(() => { $('meterFill').style.width = data.percentage + '%'; });

        const list = $('reasonsList');
        list.innerHTML = '';
        data.reasons.forEach((reason) => {
            const li = document.createElement('li');
            li.className = reason.type;
            const icon = document.createElement('i');
            icon.className = reason.type === 'risk' ? 'fa-solid fa-triangle-exclamation' : 'fa-solid fa-circle-info';
            const span = document.createElement('span');
            span.textContent = reason.text;
            li.append(icon, span);
            list.appendChild(li);
        });

    } catch (error) {
        showError('حدث خطأ أثناء الاتصال بالسيرفر.');
    } finally {
        btn.innerHTML = SCAN_LABEL;
        btn.disabled = false;
        scanner.style.display = 'none';
    }
}

// خاصية مشاركة التقرير (نسخ ملخص النتيجة للحافظة)
function shareReport() {
    const verdict = $('verdictTitle').textContent;
    const score = $('scoreValue').textContent;
    const shareText = `🛡️ نتيجة فحص منصة "MEKSHAF" للكشف عن النصب:\n📌 التقييم: ${verdict} (${score})\nاحذر ولا تشارك بياناتك السرية أبداً!`;
    
    navigator.clipboard.writeText(shareText).then(() => {
        alert('تم نسخ تقرير التحذير بنجاح! تقدر تبعته لأي حد على واتساب.');
    });
}

// جلب آخر البلاغات للشريط الحي تلقائياً
async function fetchLiveFeed() {
    try {
        const res = await fetch('api.php?action=feed');
        const data = await res.json();
        if (data.reports && data.reports.length > 0) {
            const latest = data.reports[0];
            $('feedText').textContent = `تم رصد بلاغ جديد: "${latest.scam_text}" - التقييم: ${latest.verdict}`;
        }
    } catch(e) {}
}

setInterval(fetchLiveFeed, 10000);
fetchLiveFeed();

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