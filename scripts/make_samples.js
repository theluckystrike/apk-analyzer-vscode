'use strict';
// Builds samples/sample-zovo-notes.apk for the walkthrough: a small made-up "Zovo Notes" app with a real binary XML
// manifest, two DEX files, native libraries for 3 ABIs and v1 + v2 + v3 signature data. Run: npm run samples
const fs = require('fs');
const path = require('path');
const B = require('../test/build');
const { el } = B;

const cls = (name, n, fields = 1, sup) => ({ name, methods: Array.from({ length: n }, (_, i) => (i === 0 ? '<init>' : `m${i}`)), fields, super: sup });
const pkgClasses = (pkg, names, n) => names.map((c, i) => cls(`L${pkg.replace(/\./g, '/')}/${c};`, n + (i % 4), 1 + (i % 3)));
const dex1 = {
  classes: [
    cls('Lcom/zovo/notes/MainActivity;', 14, 3, 'Landroidx/appcompat/app/AppCompatActivity;'),
    cls('Lcom/zovo/notes/EditorActivity;', 22, 5, 'Landroidx/appcompat/app/AppCompatActivity;'),
    cls('Lcom/zovo/notes/SyncService;', 9, 2, 'Landroid/app/Service;'),
    cls('Lcom/zovo/notes/BootReceiver;', 3, 0, 'Landroid/content/BroadcastReceiver;'),
    cls('Lcom/zovo/notes/NotesProvider;', 11, 2, 'Landroid/content/ContentProvider;'),
    ...pkgClasses('com.zovo.notes.data', ['Note', 'NoteDao', 'NotesDatabase', 'Tag', 'Converters'], 8),
    ...pkgClasses('com.zovo.notes.ui', ['NoteAdapter', 'NoteViewHolder', 'TagChip', 'ColorPicker'], 10),
    ...pkgClasses('androidx.core.app', ['NotificationCompat', 'ActivityCompat', 'NotificationManagerCompat'], 30),
    ...pkgClasses('androidx.recyclerview.widget', ['RecyclerView', 'LinearLayoutManager', 'DiffUtil', 'ItemTouchHelper'], 60),
    ...pkgClasses('androidx.appcompat.app', ['AppCompatActivity', 'AppCompatDelegate', 'AlertDialog'], 45),
  ],
  refs: [['Landroid/app/Activity;', 'onCreate'], ['Landroid/app/Activity;', 'setContentView'], ['Landroid/content/Context;', 'getSystemService'], ['Ljava/lang/Object;', '<init>'], ['Ljava/lang/String;', 'valueOf'], ['Landroid/util/Log;', 'd']],
  strings: ['https://sync.zovo.example/api/v1/notes', 'notes.db', 'SELECT * FROM notes ORDER BY updated DESC'],
};
const dex2 = {
  classes: [
    ...pkgClasses('kotlin', ['Unit', 'Pair', 'Result', 'Lazy', 'KotlinNullPointerException'], 12),
    ...pkgClasses('kotlin.collections', ['CollectionsKt', 'ArraysKt', 'MapsKt', 'SetsKt'], 70),
    ...pkgClasses('kotlinx.coroutines', ['BuildersKt', 'Dispatchers', 'Job', 'CoroutineScope'], 25),
    ...pkgClasses('okhttp3', ['OkHttpClient', 'Request', 'Response', 'Call', 'Interceptor', 'HttpUrl'], 35),
    ...pkgClasses('okio', ['Buffer', 'ByteString', 'Okio'], 50),
  ],
  refs: [['Ljava/lang/Object;', '<init>'], ['Ljava/net/Socket;', 'connect'], ['Ljavax/net/ssl/SSLSocketFactory;', 'createSocket']],
};
const manifest = B.axml(el('manifest', [['versionCode', 42, 'int'], ['versionName', '2.4.1'], ['compileSdkVersion', 34, 'int'], ['package', 'com.zovo.notes', 'str', '']], [
  el('uses-sdk', [['minSdkVersion', 24, 'int'], ['targetSdkVersion', 34, 'int']]),
  ...['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.CAMERA', 'android.permission.READ_MEDIA_IMAGES', 'android.permission.POST_NOTIFICATIONS', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.FOREGROUND_SERVICE', 'android.permission.SCHEDULE_EXACT_ALARM'].map((p) => el('uses-permission', [['name', p]])),
  el('application', [['label', 'Zovo Notes'], ['allowBackup', false, 'bool'], ['usesCleartextTraffic', false, 'bool'], ['extractNativeLibs', false, 'bool']], [
    el('activity', [['name', '.MainActivity'], ['exported', true, 'bool']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.MAIN']]), el('category', [['name', 'android.intent.category.LAUNCHER']])])]),
    el('activity', [['name', '.EditorActivity'], ['exported', true, 'bool']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.SEND']]), el('category', [['name', 'android.intent.category.DEFAULT']]), el('data', [['mimeType', 'text/plain']])])]),
    el('service', [['name', '.SyncService'], ['exported', false, 'bool'], ['permission', 'android.permission.BIND_JOB_SERVICE']]),
    el('receiver', [['name', '.BootReceiver'], ['exported', true, 'bool']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.BOOT_COMPLETED']])])]),
    el('provider', [['name', '.NotesProvider'], ['authorities', 'com.zovo.notes.provider'], ['exported', false, 'bool']]),
  ]),
]));
const filler = (n, seed) => { const b = Buffer.alloc(n); let x = seed; for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; b[i] = (x >>> 24) & (i % 7 ? 0xff : 0x3f); } return b; };
const files = [
  { name: 'AndroidManifest.xml', data: manifest },
  { name: 'classes.dex', data: B.dex(dex1) },
  { name: 'classes2.dex', data: B.dex(dex2) },
  { name: 'resources.arsc', data: filler(6000, 1), method: 0 },
  { name: 'res/drawable-xxhdpi/ic_launcher.png', data: filler(4200, 2), method: 0 },
  { name: 'res/drawable-xhdpi/ic_launcher.png', data: filler(2600, 3), method: 0 },
  { name: 'res/layout/activity_main.xml', data: Buffer.alloc(900, 0x41) },
  { name: 'res/layout/activity_editor.xml', data: Buffer.alloc(1200, 0x42) },
  { name: 'assets/fonts/notes-serif.ttf', data: filler(5000, 4) },
  { name: 'assets/help.html', data: Buffer.from('<html><body><h1>Zovo Notes</h1><p>Sample file for APK Analyzer.</p></body></html>\n'.repeat(20)) },
  { name: 'lib/arm64-v8a/libnotes-search.so', data: filler(3800, 5) },
  { name: 'lib/armeabi-v7a/libnotes-search.so', data: filler(3200, 6) },
  { name: 'lib/x86_64/libnotes-search.so', data: filler(3900, 7) },
  { name: 'kotlin/kotlin.kotlin_builtins', data: filler(700, 8) },
  { name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0\r\nCreated-By: APK Analyzer sample\r\n' },
  { name: 'META-INF/CERT.SF', data: 'Signature-Version: 1.0\r\n' },
  { name: 'META-INF/CERT.RSA', data: B.pkcs7() },
];
const apk = B.zip(files, { sigBlock: B.sigBlock([[0x7109871a, B.v2Value()], [0xf05368c0, B.v2Value()]]) });
const out = path.join(__dirname, '..', 'samples', 'sample-zovo-notes.apk');
fs.writeFileSync(out, apk);
console.log(`${out}: ${apk.length} bytes`);
