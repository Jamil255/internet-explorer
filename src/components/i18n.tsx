'use client';
import { createContext, useCallback, useContext, useEffect, useState } from 'react';

export const LANGS = [
  { code: 'en', name: 'English', native: 'English', dir: 'ltr' },
  { code: 'ur', name: 'Urdu', native: 'اردو', dir: 'rtl' },
  { code: 'hi', name: 'Hindi', native: 'हिन्दी', dir: 'ltr' },
  { code: 'ar', name: 'Arabic', native: 'العربية', dir: 'rtl' },
  { code: 'es', name: 'Spanish', native: 'Español', dir: 'ltr' },
  { code: 'fr', name: 'French', native: 'Français', dir: 'ltr' },
  { code: 'de', name: 'German', native: 'Deutsch', dir: 'ltr' },
  { code: 'zh', name: 'Chinese', native: '中文', dir: 'ltr' },
] as const;
export type Lang = (typeof LANGS)[number]['code'];

type Dict = Record<string, string>;

// Interface strings. Lesson content itself is written in English.
const T: Record<Exclude<Lang, 'en'>, Dict> = {
  ur: {
    'Built by': 'بنانے والا', Play: 'چلائیں', Pause: 'روکیں', Reset: 'ری سیٹ',
    'Learn how the internet works': 'سیکھیں انٹرنیٹ کیسے کام کرتا ہے',
    'Search protocols & steps': 'پروٹوکول اور مراحل تلاش کریں',
    'Learning progress': 'سیکھنے کی پیش رفت',
    'OSI layer': 'OSI لیئر',
    'Internet protocols': 'انٹرنیٹ پروٹوکولز',
    All: 'سب', Core: 'بنیادی', Application: 'ایپلیکیشن', Security: 'سیکیورٹی',
    'Protocol overview': 'پروٹوکول کا جائزہ', 'Step details': 'مرحلے کی تفصیل', Summary: 'خلاصہ',
    Overview: 'جائزہ', Active: 'فعال', 'Start lesson': 'سبق شروع کریں', 'Lesson complete': 'سبق مکمل',
    Replay: 'دوبارہ چلائیں', 'Next lesson': 'اگلا سبق', 'Packets in this step': 'اس مرحلے کے پیکٹس',
    Step: 'مرحلہ', of: 'میں سے', Packet: 'پیکٹ', 'Packet flow': 'پیکٹ فلو',
    'No.': 'نمبر', Time: 'وقت', Source: 'ماخذ', Destination: 'منزل', Protocol: 'پروٹوکول', Info: 'معلومات', Size: 'سائز',
    captured: 'کیپچر', 'click a row to inspect': 'جانچنے کے لیے قطار پر کلک کریں',
    'No packets yet — press Play or → to start.': 'ابھی کوئی پیکٹ نہیں — شروع کرنے کے لیے Play یا → دبائیں۔',
    Network: 'نیٹ ورک', Sequence: 'ترتیب', Protocols: 'پروٹوکولز', Done: 'مکمل',
    'Keyboard shortcuts': 'کی بورڈ شارٹ کٹس', Language: 'زبان', Layer: 'لیئر',
  },
  hi: {
    'Built by': 'निर्माता', Play: 'चलाएँ', Pause: 'रोकें', Reset: 'रीसेट',
    'Learn how the internet works': 'जानिए इंटरनेट कैसे काम करता है',
    'Search protocols & steps': 'प्रोटोकॉल और चरण खोजें',
    'Learning progress': 'सीखने की प्रगति', 'OSI layer': 'OSI लेयर', 'Internet protocols': 'इंटरनेट प्रोटोकॉल',
    All: 'सभी', Core: 'मूल', Application: 'एप्लिकेशन', Security: 'सुरक्षा',
    'Protocol overview': 'प्रोटोकॉल अवलोकन', 'Step details': 'चरण विवरण', Summary: 'सारांश',
    Overview: 'अवलोकन', Active: 'सक्रिय', 'Start lesson': 'पाठ शुरू करें', 'Lesson complete': 'पाठ पूरा',
    Replay: 'फिर से चलाएँ', 'Next lesson': 'अगला पाठ', 'Packets in this step': 'इस चरण के पैकेट',
    Step: 'चरण', of: 'में से', Packet: 'पैकेट', 'Packet flow': 'पैकेट प्रवाह',
    'No.': 'क्र.', Time: 'समय', Source: 'स्रोत', Destination: 'गंतव्य', Protocol: 'प्रोटोकॉल', Info: 'जानकारी', Size: 'आकार',
    captured: 'कैप्चर', 'click a row to inspect': 'जाँचने के लिए पंक्ति पर क्लिक करें',
    'No packets yet — press Play or → to start.': 'अभी कोई पैकेट नहीं — शुरू करने के लिए Play या → दबाएँ।',
    Network: 'नेटवर्क', Sequence: 'क्रम', Protocols: 'प्रोटोकॉल', Done: 'पूरा',
    'Keyboard shortcuts': 'कीबोर्ड शॉर्टकट', Language: 'भाषा', Layer: 'लेयर',
  },
  ar: {
    'Built by': 'من إنشاء', Play: 'تشغيل', Pause: 'إيقاف', Reset: 'إعادة ضبط',
    'Learn how the internet works': 'تعلّم كيف يعمل الإنترنت',
    'Search protocols & steps': 'ابحث في البروتوكولات والخطوات',
    'Learning progress': 'تقدّم التعلّم', 'OSI layer': 'طبقة OSI', 'Internet protocols': 'بروتوكولات الإنترنت',
    All: 'الكل', Core: 'أساسي', Application: 'التطبيقات', Security: 'الأمان',
    'Protocol overview': 'نظرة عامة', 'Step details': 'تفاصيل الخطوة', Summary: 'الملخّص',
    Overview: 'نظرة عامة', Active: 'نشط', 'Start lesson': 'ابدأ الدرس', 'Lesson complete': 'اكتمل الدرس',
    Replay: 'إعادة', 'Next lesson': 'الدرس التالي', 'Packets in this step': 'حزم هذه الخطوة',
    Step: 'الخطوة', of: 'من', Packet: 'حزمة', 'Packet flow': 'تدفّق الحزم',
    'No.': 'رقم', Time: 'الوقت', Source: 'المصدر', Destination: 'الوجهة', Protocol: 'البروتوكول', Info: 'المعلومات', Size: 'الحجم',
    captured: 'ملتقطة', 'click a row to inspect': 'انقر على صف لفحصه',
    'No packets yet — press Play or → to start.': 'لا حزم بعد — اضغط تشغيل أو → للبدء.',
    Network: 'الشبكة', Sequence: 'التسلسل', Protocols: 'البروتوكولات', Done: 'تم',
    'Keyboard shortcuts': 'اختصارات لوحة المفاتيح', Language: 'اللغة', Layer: 'الطبقة',
  },
  es: {
    'Built by': 'Creado por', Play: 'Reproducir', Pause: 'Pausa', Reset: 'Reiniciar',
    'Learn how the internet works': 'Aprende cómo funciona internet',
    'Search protocols & steps': 'Buscar protocolos y pasos',
    'Learning progress': 'Progreso', 'OSI layer': 'Capa OSI', 'Internet protocols': 'Protocolos de internet',
    All: 'Todos', Core: 'Base', Application: 'Aplicación', Security: 'Seguridad',
    'Protocol overview': 'Resumen del protocolo', 'Step details': 'Detalles del paso', Summary: 'Resumen',
    Overview: 'Resumen', Active: 'Activo', 'Start lesson': 'Empezar lección', 'Lesson complete': 'Lección completada',
    Replay: 'Repetir', 'Next lesson': 'Siguiente lección', 'Packets in this step': 'Paquetes de este paso',
    Step: 'Paso', of: 'de', Packet: 'Paquete', 'Packet flow': 'Flujo de paquetes',
    'No.': 'N.º', Time: 'Tiempo', Source: 'Origen', Destination: 'Destino', Protocol: 'Protocolo', Info: 'Info', Size: 'Tamaño',
    captured: 'capturados', 'click a row to inspect': 'haz clic en una fila para inspeccionarla',
    'No packets yet — press Play or → to start.': 'Aún no hay paquetes — pulsa Play o → para empezar.',
    Network: 'Red', Sequence: 'Secuencia', Protocols: 'Protocolos', Done: 'Hecho',
    'Keyboard shortcuts': 'Atajos de teclado', Language: 'Idioma', Layer: 'Capa',
  },
  fr: {
    'Built by': 'Créé par', Play: 'Lecture', Pause: 'Pause', Reset: 'Réinitialiser',
    'Learn how the internet works': 'Comprendre comment fonctionne internet',
    'Search protocols & steps': 'Rechercher protocoles et étapes',
    'Learning progress': 'Progression', 'OSI layer': 'Couche OSI', 'Internet protocols': 'Protocoles internet',
    All: 'Tous', Core: 'Base', Application: 'Application', Security: 'Sécurité',
    'Protocol overview': 'Aperçu du protocole', 'Step details': 'Détails de l’étape', Summary: 'Résumé',
    Overview: 'Aperçu', Active: 'Actif', 'Start lesson': 'Commencer', 'Lesson complete': 'Leçon terminée',
    Replay: 'Rejouer', 'Next lesson': 'Leçon suivante', 'Packets in this step': 'Paquets de cette étape',
    Step: 'Étape', of: 'sur', Packet: 'Paquet', 'Packet flow': 'Flux de paquets',
    'No.': 'N°', Time: 'Temps', Source: 'Source', Destination: 'Destination', Protocol: 'Protocole', Info: 'Infos', Size: 'Taille',
    captured: 'capturés', 'click a row to inspect': 'cliquez sur une ligne pour l’inspecter',
    'No packets yet — press Play or → to start.': 'Aucun paquet — appuyez sur Play ou → pour commencer.',
    Network: 'Réseau', Sequence: 'Séquence', Protocols: 'Protocoles', Done: 'Fini',
    'Keyboard shortcuts': 'Raccourcis clavier', Language: 'Langue', Layer: 'Couche',
  },
  de: {
    'Built by': 'Erstellt von', Play: 'Abspielen', Pause: 'Pause', Reset: 'Zurücksetzen',
    'Learn how the internet works': 'So funktioniert das Internet',
    'Search protocols & steps': 'Protokolle und Schritte suchen',
    'Learning progress': 'Lernfortschritt', 'OSI layer': 'OSI-Schicht', 'Internet protocols': 'Internetprotokolle',
    All: 'Alle', Core: 'Basis', Application: 'Anwendung', Security: 'Sicherheit',
    'Protocol overview': 'Protokollübersicht', 'Step details': 'Schrittdetails', Summary: 'Zusammenfassung',
    Overview: 'Übersicht', Active: 'Aktiv', 'Start lesson': 'Lektion starten', 'Lesson complete': 'Lektion abgeschlossen',
    Replay: 'Wiederholen', 'Next lesson': 'Nächste Lektion', 'Packets in this step': 'Pakete in diesem Schritt',
    Step: 'Schritt', of: 'von', Packet: 'Paket', 'Packet flow': 'Paketfluss',
    'No.': 'Nr.', Time: 'Zeit', Source: 'Quelle', Destination: 'Ziel', Protocol: 'Protokoll', Info: 'Info', Size: 'Größe',
    captured: 'erfasst', 'click a row to inspect': 'Zeile anklicken zum Untersuchen',
    'No packets yet — press Play or → to start.': 'Noch keine Pakete — Play oder → drücken.',
    Network: 'Netzwerk', Sequence: 'Sequenz', Protocols: 'Protokolle', Done: 'Fertig',
    'Keyboard shortcuts': 'Tastenkürzel', Language: 'Sprache', Layer: 'Schicht',
  },
  zh: {
    'Built by': '作者', Play: '播放', Pause: '暂停', Reset: '重置',
    'Learn how the internet works': '了解互联网如何运作',
    'Search protocols & steps': '搜索协议和步骤',
    'Learning progress': '学习进度', 'OSI layer': 'OSI 层', 'Internet protocols': '互联网协议',
    All: '全部', Core: '核心', Application: '应用', Security: '安全',
    'Protocol overview': '协议概览', 'Step details': '步骤详情', Summary: '总结',
    Overview: '概览', Active: '进行中', 'Start lesson': '开始课程', 'Lesson complete': '课程完成',
    Replay: '重播', 'Next lesson': '下一课', 'Packets in this step': '本步骤的数据包',
    Step: '步骤', of: '/', Packet: '数据包', 'Packet flow': '数据包流',
    'No.': '序号', Time: '时间', Source: '源', Destination: '目的', Protocol: '协议', Info: '信息', Size: '大小',
    captured: '已捕获', 'click a row to inspect': '点击一行进行检查',
    'No packets yet — press Play or → to start.': '还没有数据包 — 按播放或 → 开始。',
    Network: '网络', Sequence: '时序', Protocols: '协议', Done: '完成',
    'Keyboard shortcuts': '键盘快捷键', Language: '语言', Layer: '层',
  },
};

const Ctx = createContext<{ lang: Lang; setLang: (l: Lang) => void; t: (s: string) => string }>({
  lang: 'en',
  setLang: () => {},
  t: (s) => s,
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>('en');
  useEffect(() => {
    try {
      const saved = localStorage.getItem('nx:lang') as Lang | null;
      if (saved && LANGS.some((l) => l.code === saved)) setLangState(saved);
    } catch {}
  }, []);
  useEffect(() => {
    const info = LANGS.find((l) => l.code === lang)!;
    document.documentElement.lang = lang;
    document.documentElement.dir = info.dir;
  }, [lang]);
  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem('nx:lang', l);
    } catch {}
  }, []);
  const t = useCallback((s: string) => (lang === 'en' ? s : T[lang][s] ?? s), [lang]);
  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>;
}

export const useT = () => useContext(Ctx);
