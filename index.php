<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>كاشف النصب - Scam Detector</title>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="container">
    <div class="header">
        <h1><i class="fa-solid fa-shield-halved"></i>MEKSHAF</h1>
        <p>منصة الكشف الفوري عن الاحتيال الرقمي والرسائل المضللة بالعامية المصرية</p>
    </div>

    <!-- أمثلة الفحص السريع -->
    <div class="quick-tests">
        <span style="font-size: 13px; color: var(--text-dim); align-self: center;">تجربة سريعة:</span>
        <button class="quick-btn" type="button" onclick="loadExample('vodafone')">🎁 جائزة فودافون</button>
        <button class="quick-btn" type="button" onclick="loadExample('bank')">🏦 تحديث بنكي</button>
        <button class="quick-btn" type="button" onclick="loadExample('safe')">✉️ رسالة عادية</button>
    </div>

    <div class="input-group">
        <div class="scanner-line" id="scannerLine"></div>
        <textarea id="inputText" dir="auto" maxlength="3000" aria-label="النص أو الرابط المراد فحصه"
            placeholder="ضع النص المشبوه أو الرابط هنا..."></textarea>
    </div>
    
    <div class="meta-bar">
        <span class="hint"><i class="fa-regular fa-keyboard"></i> اختصار: Ctrl + Enter للفحص</span>
        <div class="counter"><span id="charCount">0</span> / 3000</div>
    </div>

    <div class="actions">
        <button class="btn-scan" id="scanBtn" type="button">
            <i class="fa-solid fa-magnifying-glass"></i> افحص دلوقتي
        </button>
        <button class="btn-clear" id="clearBtn" type="button">مسح</button>
    </div>

    <div id="errorBox" class="error-box" role="alert"></div>

    <div id="resultCard" class="result-card" aria-live="polite">
        <div class="result-header">
            <h3 id="verdictTitle">نتيجة الفحص</h3>
            <span class="score-val" id="scoreValue">0%</span>
        </div>
        <div class="meter"><div class="meter-fill" id="meterFill"></div></div>
        <ul class="reasons-list" id="reasonsList"></ul>
        <button class="btn-share" type="button" onclick="shareReport()">
            <i class="fa-solid fa-share-nodes"></i> مشاركة التقرير وتحذير الأصدقاء
        </button>
    </div>
</div>

<!-- الشريط الحي للبلاغات المجتمعية المجهولة -->
<div class="live-feed">
    <div class="feed-title"><i class="fa-solid fa-rss"></i> رادار النصب:</div>
    <div class="feed-content" id="feedText">جاري تحميل أحدث البلاغات المجتمعية...</div>
</div>

<script src="script.js"></script>
</body>
</html>