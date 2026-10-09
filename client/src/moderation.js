// =========================================================
// ENCRYPTO MODERATION ENGINE v2
// Context-aware + obfuscation-resistant risk detection.
// - Normalizes leet, separators, repeats, spaced letters
// - CRITICAL/HIGH always win over benign context
// - MEDIUM/LOW suppressed by clear media/education context
// - Multi-signal escalation: 2x MEDIUM -> HIGH, 3x LOW -> MEDIUM
// Levels: NONE, LOW, MEDIUM, HIGH, CRITICAL
// =========================================================

const LEVEL_ORDER = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// =========================================================
// BENIGN CONTEXT (unchanged + idioms)
// =========================================================

const BENIGN_CONTEXT_PATTERNS = [
  /\b(?:movie|film|films|show|series|episode|documentary|documentary film)\b/i,
  /\b(?:watched|watching|saw|seen)\b.{0,60}\b(?:movie|film|show|series|episode)\b/i,
  /\b(?:movie|film|show|series|episode)\b.{0,80}\b(?:about|with|containing|contains|had|has|scene|scenes)\b/i,
  /\b(?:game|gaming|video game|videogame|gameplay|mission|level|character)\b/i,
  /\b(?:played|playing)\b.{0,60}\b(?:game|games)\b/i,
  /\b(?:book|novel|story|stories|fiction|chapter|comic|comics|manga)\b/i,
  /\b(?:character|characters|protagonist|villain|fictional)\b/i,
  /\b(?:read|reading)\b.{0,80}\b(?:book|novel|story|article|chapter)\b/i,
  /\b(?:news|newspaper|article|report|reporting|journalist|journalism)\b/i,
  /\b(?:headline|headlines|documented|reported|according to)\b/i,
  /\b(?:history|historical|history class|school|college|university|lecture|lesson)\b/i,
  /\b(?:studied|study|studying|learned|learning|research|researching)\b/i,
  /\b(?:exam|assignment|homework|textbook|academic|educational)\b/i,
  /\b(?:discuss|discussion|discussing|explain|explaining|meaning|definition)\b/i,
  /\b(?:what does|what is|what are|tell me about|information about)\b/i,
  /\b(?:fictional|imaginary|fantasy|fantasy story|roleplay|role-play|role playing)\b/i,
  /\b(?:pretend|pretending|hypothetical|hypothetically)\b/i,
];

const STRONG_BENIGN_CONTEXT_PATTERNS = [
  /\b(?:watched|watching|saw|seen)\b.{0,80}\b(?:movie|film|show|series|episode)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,
  /\b(?:movie|film|show|series|episode)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,
  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:movie|film|show|series|episode)\b/i,
  /\b(?:game|gaming|gameplay|video game)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,
  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:game|gaming|gameplay|video game)\b/i,
  /\b(?:book|novel|story|fiction|chapter|comic|manga)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,
  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:book|novel|story|fiction|chapter|comic|manga)\b/i,
  /\b(?:news|article|report|newspaper|journalist|journalism)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion|terrorism)\b/i,
  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion|terrorism)\b.{0,100}\b(?:news|article|report|newspaper|journalist|journalism)\b/i,
  /\b(?:history|historical|school|college|university|lecture|lesson|research|studied|study|textbook)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|war|terrorism)\b/i,
  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|war|terrorism)\b.{0,100}\b(?:history|historical|school|college|university|lecture|lesson|research|studied|study|textbook)\b/i,
];

// Idioms that contain dangerous words but are never threats on their own.
// Only suppress MEDIUM/LOW, never CRITICAL/HIGH.
const IDIOM_EXCEPTIONS = [
  /\bkill\s+time\b/i,
  /\bkiller\s+(?:app|deal|whale|instinct|combo|move)\b/i,
  /\bkill\s+the\s+lights\b/i,
  /\bbomb\s+test\b/i,
  /\bwater\s+gun\b/i,
  /\bglue\s+gun\b/i,
  /\bkill\s+feed\b/i,
  /\bkill\s+streak\b/i,
];

// =========================================================
// CRITICAL — explicit intent to kill/harm a target
// Always wins, even with benign words elsewhere.
// =========================================================

const VIOLENT_VERBS = "(?:kill|murder|stab|shoot|strangle|choke|hang|behead|decapitate|slaughter|execute|assassinate|slit|torture|poison|drown|burn|crush|smash|rape|gun down|run over|blow up|bomb)";

const CRITICAL_RULES = [
  {
    level: "CRITICAL",
    category: "DIRECT_THREAT",
    score: 100,
    reason: "Direct violent threat detected.",
    patterns: [
      new RegExp(`\\bi\\s*(?:am|'m|will|'ll|gonna)\\s+(?:going\\s+to|gonna)?\\s*${VIOLENT_VERBS}\\b.{0,40}\\b(?:you|u|him|her|them|your family|your kids|your wife|your husband|everyone|everybody|all of you)\\b`, "i"),
      new RegExp(`\\bi\\s+(?:plan|intend|swear|promise|threaten)\\s+to\\s+${VIOLENT_VERBS}\\b`, "i"),
      new RegExp(`\\b(?:going\\s+to|plan\\s+to|intend\\s+to|gonna)\\s+${VIOLENT_VERBS}\\b.{0,30}\\b(?:you|him|her|them)\\b`, "i"),
      new RegExp(`\\bi\\s*(?:am|'m)\\s+going\\s+to\\s+(?:hurt|harm|destroy)\\s+you\\b`, "i"),
      new RegExp(`\\bi\\s+will\\s+(?:hurt|harm|destroy)\\s+you\\b`, "i"),
      // expanded: "i'll slit your throat", "i will strangle her"
      new RegExp(`\\bi(?:'ll| will)\\s+(?:slit|cut)\\s+(?:your|his|her|their)\\s+throat\\b`, "i"),
      new RegExp(`\\bi\\s+will\\s+(?:strangle|choke|hang|behead|burn|drown|poison)\\b.{0,30}\\b(?:you|him|her|them)\\b`, "i"),
    ],
  },
  {
    level: "CRITICAL",
    category: "DIRECT_THREAT",
    score: 100,
    reason: "Death threat against recipient detected.",
    patterns: [
      /\byou\s+(?:will|gon\s*na|gonna)\s+die\b/i,
      /\byou\s*are\s+dead\b/i,
      /\byou(?:'re|r)\s+dead\b/i,
      /\byou(?:'ll| will)\s+(?:die|be killed|be murdered|get shot|get stabbed)\b/i,
      /\bwatch\s+your\s+back\b.{0,30}\b(?:kill|die|dead|hurt)\b/i,
      /\bi\s+know\s+where\s+you\s+live\b.{0,40}\b(?:kill|die|dead|hurt|come for)\b/i,
      /\bi\s*am\s+outside\s+(?:your|ur)\s+(?:house|home|door|school|work)\b/i,
    ],
  },
  {
    level: "CRITICAL",
    category: "DIRECT_THREAT",
    score: 100,
    reason: "Mass-attack intent detected.",
    patterns: [
      /\bi\s+will\s+(?:shoot\s+up|bomb|massacre|slaughter)\b.{0,40}\b(?:school|college|mosque|church|temple|concert|mall|crowd|office|workplace)\b/i,
      /\bshoot\s+up\s+(?:the\s+)?(?:school|college|office|mall|concert)\b/i,
      /\bbomb\s+(?:the\s+)?(?:school|station|airport|mall|concert|mosque|church)\b/i,
      /\bi\s+will\s+commit\s+(?:a\s+)?(?:mass shooting|mass murder|school shooting)\b/i,
    ],
  },
];

// =========================================================
// HIGH — planning, manufacturing, detailed violent action
// =========================================================

const HIGH_RULES = [
  {
    level: "HIGH",
    category: "EXPLOSIVE",
    score: 80,
    reason: "Explosive manufacturing or use detected.",
    patterns: [
      /\bhow\s+to\s+make\s+(?:a\s+)?(?:bomb|pipe bomb|molotov|explosive|detonator)\b/i,
      /\bpipe\s+bomb\b/i,
      /\bmolotov\s+cocktail\b/i,
      /\bpressure\s+cooker\s+bomb\b/i,
      /\b(?:ammonium nitrate|tannerite|gunpowder|black powder|detonator|blasting cap)\b.{0,40}\b(?:bomb|explosive|make|build|mix)\b/i,
      /\b(?:build|assemble|detonate|set off)\b.{0,30}\b(?:bomb|explosive|ied)\b/i,
      /\bi\s+(?:have|got|own|made|built)\s+(?:a\s+)?(?:bomb|pipe bomb|molotov|grenade|c4|dynamite|ied|explosive)\b/i,
      /\bthere\s+is\s+(?:a\s+)?(?:bomb|explosive|grenade)\s+(?:here|inside|in)\b/i,
      /\b(?:placed|planted|left)\s+(?:a\s+)?(?:bomb|explosive|grenade|ied)\b/i,
      /\b(?:blow\s+up|set\s+off|detonate)\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "WEAPON",
    score: 78,
    reason: "Firearm acquisition or illegal weapon detected.",
    patterns: [
      /\bak[\s\-]?47\b/i,
      /\bar[\s\-]?15\b/i,
      /\bm16\b/i,
      /\bglock\b/i,
      /\buzi\b/i,
      /\bdesert\s+eagle\b/i,
      /\bsawed.?off\b/i,
      /\bpump\s+action\b/i,
      /\bghost\s+gun\b/i,
      /\b3d\s+printed\s+gun\b/i,
      /\bbuy\s+(?:a\s+)?gun\s+(?:illegally|off the books|no questions|black market)\b/i,
      /\bsilencer|suppressor\b.{0,20}\b(?:gun|rifle|pistol)\b/i,
      /\b(?:automatic|semi.?automatic)\s+(?:rifle|weapon|gun|firearm)\b/i,
      /\bbump\s+stock\b/i,
      /\bhigh\s+capacity\s+magazine\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "ATTACK_PLANNING",
    score: 82,
    reason: "Attack planning language detected.",
    patterns: [
      /\bmass\s+shooting\b/i,
      /\bschool\s+shooting\b/i,
      /\bdrive.?by\s+shooting\b/i,
      /\bstabbing\s+spree\b/i,
      /\bhit\s+list\b/i,
      /\bkill\s+list\b/i,
      /\btarget\s+list\b.{0,20}\b(?:kill|shoot|bomb)\b/i,
      /\bhostage\s+taking\b/i,
      /\bkidnap\b.{0,30}\b(?:ransom|kill|torture|hide)\b/i,
      /\bambush\b.{0,30}\b(?:kill|shoot|attack)\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "VIOLENCE",
    score: 75,
    reason: "Detailed violent action detected.",
    patterns: [
      /\bslit\s+(?:your|his|her|their|the)\s+throat\b/i,
      /\bcut\s+(?:your|his|her|their)\s+throat\b/i,
      /\bbash\s+(?:your|his|her|their)\s+head\b/i,
      /\bbreak\s+(?:your|his|her|their)\s+neck\b/i,
      /\bstrangle|strangling|suffocate|suffocating\b/i,
      /\bburn\s+(?:you|him|her|them)\s+alive\b/i,
      /\bacid\s+attack\b/i,
      /\brun\s+(?:you|him|her|them)\s+over\s+with\s+(?:a\s+)?car\b/i,
      /\bgun\s*to\s+(?:your|his|her|their|my)\s+head\b/i,
      /\bknife\s*to\s+(?:your|his|her|their)\s+throat\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "VIOLENCE",
    score: 75,
    reason: "Arson or kidnapping intent detected.",
    patterns: [
      /\bset\s+fire\s+to\b.{0,30}\b(?:house|home|school|building|car)\b/i,
      /\bburn\s+down\b.{0,30}\b(?:house|home|school|building)\b/i,
      /\bpetrol\b.{0,20}\b(?:burn|fire|torch)\b/i,
      /\bgasoline\b.{0,20}\b(?:burn|fire|torch)\b/i,
      /\bkidnap\b.{0,30}\b(?:you|him|her|them|child|kid)\b/i,
      /\block\s+(?:you|him|her|them)\s+in\s+(?:a\s+)?(?:basement|trunk|cage|room)\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "VIOLENCE",
    score: 76,
    reason: "Direct violent action against a person detected.",
    patterns: [
      /\b(?:kill|murder|stab|shoot|strangle|choke|hang|behead)\s+(?:you|u|him|her|them|someone|people)\b/i,
      /\b(?:attack|shooting|stabbing)\s+(?:you|him|her|them|someone)\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "VIOLENCE",
    score: 75,
    reason: "Weapon and violent action detected together.",
    patterns: [
      /\b(?:gun|knife|weapon|blade|rifle|pistol|machete|axe|bat|grenade|explosive)\b.{0,60}\b(?:attack|shoot|stab|kill|hurt|murder|slaughter|torture)\b/i,
      /\b(?:attack|shoot|stab|kill|hurt|murder)\b.{0,60}\b(?:gun|knife|weapon|blade|rifle|pistol|machete|axe|bat|grenade)\b/i,
      /\b(?:bring|get|grab|take)\s+(?:a\s+)?(?:gun|knife|weapon|rifle|pistol)\b.{0,30}\b(?:kill|shoot|stab|attack|hurt)\b/i,
    ],
  },
  {
    level: "HIGH",
    category: "HARASSMENT",
    score: 72,
    reason: "Stalking combined with threat detected.",
    patterns: [
      /\bi\s+know\s+where\s+you\s+(?:live|work|study|sleep)\b/i,
      /\bi(?:'m| am)\s+(?:following|watching|stalking)\s+you\b/i,
      /\bi(?:'m| am)\s+outside\b.{0,30}\b(?:watching|waiting|coming)\b/i,
      /\bleak\s+(?:your|his|her)\s+address\b/i,
      /\bdox(?:x|ing)?\s+you\b/i,
    ],
  },
];

// =========================================================
// MEDIUM — weapons, assault threats, coercion, self-harm acts
// =========================================================

const MEDIUM_RULES = [
  {
    level: "MEDIUM",
    category: "WEAPON",
    score: 45,
    reason: "Weapon-related terminology detected.",
    patterns: [
      /\bi\s+(?:have|got|own|carry|carrying|bought|hid|hide)\s+(?:a\s+)?(?:knife|knives|blade|dagger|machete|katana|axe|hatchet|gun|pistol|revolver|rifle|shotgun|firearm|taser|stun gun|crossbow|brass knuckles|grenade|explosive|ammunition|ammo|bullets|magazine)\b/i,
      /\b(?:bring|get|take|carry|grab|buy|steal)\s+(?:a\s+)?(?:knife|gun|weapon|pistol|rifle|blade|machete|grenade|ammo)\b/i,
      /\b(?:my|your)\s+(?:knife|gun|weapon|pistol|rifle|blade|firearm|machete|grenade)\b/i,
      /\bloaded\s+(?:gun|pistol|rifle|shotgun)\b/i,
      /\bconcealed\s+(?:carry|weapon|gun|knife)\b/i,
    ],
  },
  {
    level: "MEDIUM",
    category: "THREAT_CONTEXT",
    score: 42,
    reason: "Physical assault threat detected.",
    patterns: [
      /\bi\s+will\s+(?:beat|punch|slap|kick|smash|break)\b.{0,30}\b(?:you|your face|your nose|your jaw|your legs|your arms)\b/i,
      /\bi(?:'ll| will)\s+break\s+your\b/i,
      /\bi(?:'ll| will)\s+smash\s+your\b/i,
      /\bwait\s+till\s+i\s+(?:find|catch|see)\s+you\b/i,
      /\byou(?:'ll| will)\s+regret\b.{0,20}\b(?:this|it)\b/i,
      /\bdo\s+what\s+i\s+say\s+or\s+else\b/i,
      /\bobey\s+or\s+die\b/i,
      /\bpay\s+or\s+die\b/i,
    ],
  },
  {
    level: "MEDIUM",
    category: "HARASSMENT",
    score: 40,
    reason: "Stalking or harassment pattern detected.",
    patterns: [
      /\btracking\s+you\b/i,
      /\bfollowing\s+you\s+home\b/i,
      /\bwatching\s+your\s+house\b/i,
      /\bexpose\s+you\b.{0,20}\b(?:address|photos|private)\b/i,
      /\bspread\s+your\b.{0,20}\b(?:photos|address|nudes)\b/i,
      /\brevenge\s+porn\b/i,
    ],
  },
  {
    level: "MEDIUM",
    category: "SELF_HARM",
    score: 48,
    reason: "Possible self-harm action detected.",
    patterns: [
      /\bkill\s+myself\b/i,
      /\bi\s+want\s+to\s+kill\s+myself\b/i,
      /\bi\s+want\s+to\s+die\b/i,
      /\bi\s*am\s+going\s+to\s+kill\s+myself\b/i,
      /\bsuicide\s+plan\b/i,
      /\bcutting\s+myself\b/i,
      /\bcut\s+myself\b/i,
      /\bself.?harm\b/i,
    ],
  },
];

// =========================================================
// LOW — isolated dangerous terms, extremism, ideation
// =========================================================

const LOW_RULES = [
  {
    level: "LOW",
    category: "SENSITIVE_TERM",
    score: 15,
    reason: "Potentially sensitive terminology detected.",
    patterns: [
      /\bkill\b/i,
      /\bmurder\b/i,
      /\bshoot\b/i,
      /\bstab\b/i,
      /\bbomb\b/i,
      /\bexplosive\b/i,
      /\bexplosion\b/i,
      /\bgun\b/i,
      /\brifle\b/i,
      /\bpistol\b/i,
      /\bknife\b/i,
      /\bmachete\b/i,
      /\bgrenade\b/i,
      /\bammunition\b/i,
      /\bmassacre\b/i,
      /\bassassination\b/i,
      /\bassassinate\b/i,
      /\bstrangle\b/i,
      /\bpoison\b/i,
      /\bviolence\b/i,
      /\bviolent\b/i,
      /\bweaponry\b/i,
      /\bhostage(?:s)?\b/i,
      /\bkidnap(?:ping|ped)?\b/i,
      /\btorture\b/i,
      /\bwar\b/i,
      /\bcombat\b/i,
      /\bmilitant\b/i,
      /\bshooting\b/i,
      /\bstabbing\b/i,
    ],
  },
  {
    level: "LOW",
    category: "SENSITIVE_CONTEXT",
    score: 16,
    reason: "Extremist or hate-related terminology detected.",
    patterns: [
      /\bterrorism\b/i,
      /\bterrorist\b/i,
      /\bsuicide\s+bomber\b/i,
      /\bextremist\b/i,
      /\bradicali[sz]e\b/i,
      /\bjihad\b/i,
      /\bisis\b/i,
      /\bal.?qaeda\b/i,
      /\bwhite\s+supremacist\b/i,
      /\bneo.?nazi\b/i,
      /\bhate\s+crime\b/i,
      /\blynching\b/i,
      /\bethnic\s+cleansing\b/i,
    ],
  },
  {
    level: "LOW",
    category: "SELF_HARM",
    score: 18,
    reason: "Possible self-harm ideation detected.",
    patterns: [
      /\bsuicidal\b/i,
      /\bsuicide\b/i,
      /\bkill\s+myself\b/i,
      /\bwant\s+to\s+die\b/i,
      /\bwant\s+to\s+disappear\s+forever\b/i,
      /\bno\s+reason\s+to\s+live\b/i,
      /\bend\s+it\s+all\b/i,
    ],
  },
  {
    level: "LOW",
    category: "SENSITIVE_TERM",
    score: 17,
    reason: "Sexual-violence terminology detected.",
    patterns: [
      /\brape\b/i,
      /\bmolest\b/i,
      /\bsexual\s+assault\b/i,
      /\bgrooming\b.{0,20}\b(?:child|minor|kid)\b/i,
    ],
  },
];

const RULES = [...CRITICAL_RULES, ...HIGH_RULES, ...MEDIUM_RULES, ...LOW_RULES];

// =========================================================
// NORMALIZE (obfuscation-resistant)
// =========================================================

const LEET_MAP = { 0: "o", 1: "i", 3: "e", 5: "s", 8: "b", "@": "a", $: "s", "!": "i", "+": "t" };

function normalizeText(text) {
  let s = String(text || "").normalize("NFKC").toLowerCase();
  s = s.replace(/[̀-ͯ]/g, "");
  s = s.replace(/[\u200B-\u200D\uFEFF]/g, "");
  // leet only inside words (letter-adjacent) so model numbers like AK-47 / AR-15 survive
  // "k1ll" -> "kill" but "ar 15" stays "ar 15"
  const chars = s.split("");
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const mapped = LEET_MAP[ch];
    if (!mapped) continue;
    const prev = chars[i - 1] || "";
    const next = chars[i + 1] || "";
    const prevIsLetter = /[a-z]/.test(prev);
    const nextIsLetter = /[a-z]/.test(next);
    if (prevIsLetter || nextIsLetter) chars[i] = mapped;
  }
  s = chars.join("");
  // fuse spaced single letters: "k i l l" -> "kill "
  // trailing space keeps word boundary with next word ("kill you", not "killyou")
  s = s.replace(/(?:\b[a-z]\b[\s._*\-:|/\\]*){3,}/g, (m) => m.replace(/[^a-z]/g, "") + " ");
  // separators to space, keep alphanumerics + space
  s = s.replace(/[^a-z0-9\s]/g, " ");
  // collapse repeats: kiiiill -> kiill (max 2), then common double stays
  s = s.replace(/(.)\1{2,}/g, "$1$1");
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

function hasBenignContext(n) {
  return BENIGN_CONTEXT_PATTERNS.some((p) => p.test(n));
}
function hasStrongBenignContext(n) {
  return STRONG_BENIGN_CONTEXT_PATTERNS.some((p) => p.test(n));
}
function hasIdiom(n) {
  return IDIOM_EXCEPTIONS.some((p) => p.test(n));
}
function getMatches(rules, n) {
  return rules.filter((r) => r.patterns.some((p) => { try { p.lastIndex = 0; return p.test(n); } catch { return false; } }));
}
function getStrongest(matches) {
  if (!matches.length) return null;
  return matches.reduce((best, r) => (!best || LEVEL_ORDER[r.level] > LEVEL_ORDER[best.level] ? r : best), null);
}

// =========================================================
// ANALYZE
// =========================================================

export function analyzeMessage(text) {
  const normalized = normalizeText(text);
  if (!normalized) return { flagged: false, level: "NONE", category: "", reason: "", score: 0 };

  // 1. CRITICAL always wins
  const crit = getMatches(CRITICAL_RULES, normalized);
  if (crit.length) {
    const s = getStrongest(crit);
    return { flagged: true, level: s.level, category: s.category, reason: s.reason, score: s.score };
  }

  // 2. HIGH always wins (before benign suppression)
  const high = getMatches(HIGH_RULES, normalized);
  if (high.length) {
    const s = getStrongest(high);
    const bonus = Math.min(15, (high.length - 1) * 5);
    return { flagged: true, level: s.level, category: s.category, reason: s.reason, score: Math.min(100, s.score + bonus) };
  }

  const strongBenign = hasStrongBenignContext(normalized);
  const idiom = hasIdiom(normalized);

  // 3. MEDIUM (suppressed by benign/idiom)
  const med = getMatches(MEDIUM_RULES, normalized);
  if (med.length) {
    if (strongBenign || idiom || hasBenignContext(normalized)) {
      // fall through to LOW check — benign discussion of a weapon is not MEDIUM
    } else {
      // escalation: 2+ distinct MEDIUM signals -> HIGH
      if (med.length >= 2) {
        const s = getStrongest(med);
        return { flagged: true, level: "HIGH", category: s.category, reason: "Multiple weapon/threat indicators detected.", score: 72 };
      }
      const s = getStrongest(med);
      return { flagged: true, level: s.level, category: s.category, reason: s.reason, score: s.score };
    }
  }

  // 4. LOW (suppressed by benign/idiom)
  const low = getMatches(LOW_RULES, normalized);
  if (low.length) {
    if (hasBenignContext(normalized) || idiom) {
      return { flagged: false, level: "NONE", category: "", reason: "", score: 0 };
    }
    // escalation: 3+ LOW signals -> MEDIUM
    if (low.length >= 3) {
      const s = getStrongest(low);
      return { flagged: true, level: "MEDIUM", category: s.category, reason: "Multiple sensitive terms detected together.", score: 40 };
    }
    const s = getStrongest(low);
    return { flagged: true, level: s.level, category: s.category, reason: s.reason, score: s.score };
  }

  return { flagged: false, level: "NONE", category: "", reason: "", score: 0 };
}

export function getModerationRules() {
  return RULES;
}
