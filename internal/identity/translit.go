package identity

import (
	"strings"
	"unicode"
)

// Name equivalence across spellings, scripts and nicknames.
//
// People are written many ways: Mohamed / Muhammad / Mohammed / محمد, Abdullah
// / Abd Allah / عبد الله, Bob / Robert. Exact word comparison misses all of
// them, which splits one person into several and breaks anchor matching. Each
// name word is therefore compared on three levels:
//
//	strong  identical, or listed as spellings of the same name (dictionary)
//	weak    same consonant skeleton (a transliteration-insensitive key), 3+ letters
//	none    otherwise
//
// The skeleton drops vowels and merges look-alike consonants (ث س ش ص → s,
// ت ط → t, ك ق → k, "kh" → x …), so the Arabic and Latin spellings of one
// name meet at the same key. Skeleton-only matches are *weak* on purpose:
// Hassan / Hussein / Hosni share one, and must not be merged on that alone.

// normalizeArabic removes diacritics and tatweel and unifies letter variants.
func normalizeArabic(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0x064B && r <= 0x065F, r == 0x0670, r == 0x0640:
			continue
		case r == 'أ' || r == 'إ' || r == 'آ' || r == 'ٱ':
			b.WriteRune('ا')
		case r == 'ى' || r == 'ئ':
			b.WriteRune('ي')
		case r == 'ة':
			b.WriteRune('ه')
		case r == 'ؤ':
			b.WriteRune('و')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isArabic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Arabic, r) {
			return true
		}
	}
	return false
}

var arabicSkeleton = map[rune]string{
	'ب': "b", 'ت': "t", 'ث': "s", 'ج': "g", 'ح': "h", 'خ': "x", 'د': "d", 'ذ': "z", 'ر': "r", 'ز': "z",
	'س': "s", 'ش': "s", 'ص': "s", 'ض': "d", 'ط': "t", 'ظ': "z", 'غ': "g", 'ف': "f", 'ق': "k", 'ك': "k",
	'ل': "l", 'م': "m", 'ن': "n", 'ه': "h", 'گ': "g", 'پ': "b",
	// ع ء و ي ا (and their forms) are vowels / glottal sounds: dropped
}

// skeleton reduces a name word to a script-independent consonant key.
func skeleton(w string) string {
	w = normalizeArabic(strings.ToLower(w))
	if isArabic(w) {
		w = strings.TrimPrefix(w, "ال") // the article
		var b strings.Builder
		var last string
		for _, r := range w {
			if c, ok := arabicSkeleton[r]; ok && c != last {
				b.WriteString(c)
				last = c
			}
		}
		return b.String()
	}
	w = strings.NewReplacer("kh", "x", "gh", "g", "sh", "s", "th", "s", "dh", "z", "ph", "f", "ch", "s", "ck", "k").Replace(fold(w))
	var b strings.Builder
	var last rune
	for _, r := range w {
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'y', 'w', ' ':
			continue
		case 'j':
			r = 'g'
		case 'q', 'c':
			r = 'k'
		case 'v':
			r = 'f'
		case 'p':
			r = 'b'
		}
		if r != last {
			b.WriteRune(r)
			last = r
		}
	}
	return b.String()
}

// nameGroups lists spellings of the same given name or nickname. Arabic forms
// are written naturally and normalised at start-up.
var nameGroups = []string{
	// Arabic names
	"mohamed mohammed muhammad mohammad muhammed mohamad mohmed mahmed muhamed محمد",
	"ahmed ahmad ahmet احمد", "mahmoud mahmood mahmud محمود", "mostafa mustafa moustafa mustapha مصطفى",
	"ibrahim ebrahim ibraheem ابراهيم", "ismail ismael ismaeel isma3il اسماعيل", "youssef yusuf yousef yussef yusef يوسف",
	"omar umar omer عمر", "amr amro عمرو", "ali aly علي", "hassan hasan حسن", "hussein hussain hosein husain حسين",
	"hossam husam حسام", "khaled khalid خالد", "tarek tariq tareq طارق", "sherif sharif شريف", "osama usama اسامة",
	"karim kareem كريم", "abdullah abdallah abdulla abdalla عبدالله", "abdelrahman abdulrahman abdelrahmane abderrahman عبدالرحمن",
	"abdelaziz abdulaziz عبدالعزيز", "abdelhamid abdulhamid عبدالحميد", "abdelfattah abdulfattah عبدالفتاح",
	"mina mena مينا", "mariam maryam مريم", "fatma fatima fatimah فاطمة", "aisha aysha ayesha عائشة", "zeinab zainab zaynab زينب",
	"nour noor nur نور", "yasmin yasmine jasmine ياسمين", "sara sarah سارة", "hany hani هاني", "wael wail وائل",
	"waleed walid وليد", "samir sameer سمير", "samy sami سامي", "adel adil عادل", "essam isam عصام", "emad imad عماد",
	"ayman aiman ايمن", "hesham hisham هشام", "mazen mazin مازن", "ziad ziyad زياد", "bassem basem باسم", "hazem hazim حازم",
	"mamdouh mamdoh ممدوح", "magdy majdy majdi مجدي", "nabil نبيل", "rami ramy رامي", "salah salah صلاح", "salem salim سالم",
	"saad saad سعد", "yasser yasir ياسر", "mohsen mohsin محسن", "hamza حمزة", "bilal بلال", "anas انس", "ammar عمار", "malek malik مالك",
	"sayed sayyid sayed سيد", "gamal jamal جمال", "gaber jaber جابر", "gad jad جاد", "nader nadir نادر", "ashraf اشرف", "ehab ihab ايهاب",
	// English forms and nicknames
	"robert bob rob bobby", "william bill will billy", "elizabeth liz beth betty", "michael mike mick",
	"james jim jimmy jamie", "david dave davy", "thomas tom tommy", "richard rick dick rich",
	"charles charlie chuck", "joseph joe joey", "daniel dan danny", "matthew matt", "christopher chris",
	"anthony tony", "andrew andy drew", "alexander alex", "katherine catherine kate katie kathy", "jennifer jen jenny",
	"margaret maggie meg peggy", "patricia pat patty tricia", "stephen steven steve", "nicholas nick", "samuel sam",
	"benjamin ben", "edward ed eddie ted", "jonathan jon", "timothy tim", "kenneth ken", "ronald ron", "donald don",
	"gregory greg", "peter pete", "geoffrey jeffrey jeff",
}

var groupOf = map[string]int{}

func init() {
	for i, g := range nameGroups {
		for _, f := range strings.Fields(g) {
			key := normalizeArabic(strings.ToLower(f))
			if !isArabic(key) {
				key = fold(key)
			}
			if _, taken := groupOf[key]; !taken {
				groupOf[key] = i + 1
			}
		}
	}
}

func groupID(w string) int {
	w = normalizeArabic(strings.ToLower(w))
	if !isArabic(w) {
		w = fold(w)
	}
	return groupOf[w]
}

// tokenLevel compares two name words: 2 strong, 1 weak, 0 none.
func tokenLevel(a, b string) int {
	na, nb := normalizeArabic(strings.ToLower(a)), normalizeArabic(strings.ToLower(b))
	if !isArabic(na) {
		na = fold(na)
	}
	if !isArabic(nb) {
		nb = fold(nb)
	}
	if na == nb {
		return 2
	}
	if ga, gb := groupID(na), groupID(nb); ga != 0 && ga == gb {
		return 2
	}
	if sa, sb := skeleton(na), skeleton(nb); len(sa) >= 3 && sa == sb {
		return 1
	}
	return 0
}

// compoundPrefix words that belong to the next word ("Abd" + "Allah").
var compoundPrefix = map[string]bool{
	"abd": true, "abdel": true, "abdul": true, "abdal": true, "abu": true, "abo": true, "bin": true, "ibn": true,
	"عبد": true, "ابو": true, "بن": true, "ابن": true,
}

// articles that carry no identity ("El-Sayed", "Al Sayed", "السيد").
var articles = map[string]bool{"el": true, "al": true, "ال": true}

// nameTokens splits a name into comparable words: diacritics removed,
// compound prefixes merged with their next word, articles dropped.
func nameTokens(name string) []string {
	var raw []string
	for _, w := range strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) {
			return r
		}
		return ' '
	}, name)) {
		w = normalizeArabic(strings.ToLower(w))
		if !isArabic(w) {
			w = fold(w)
		}
		if w != "" {
			raw = append(raw, w)
		}
	}
	var out []string
	for i := 0; i < len(raw); i++ {
		w := raw[i]
		if articles[w] && i+1 < len(raw) {
			continue
		}
		if compoundPrefix[w] && i+1 < len(raw) {
			next := raw[i+1]
			if articles[next] && i+2 < len(raw) { // "abd el rahman"
				next = raw[i+2]
				i++
			}
			w += next
			i++
		}
		for _, art := range []string{"el", "al"} { // "elsayed" -> "sayed"
			if strings.HasPrefix(w, art) && len(w) >= len(art)+4 && !isArabic(w) && groupID(w) == 0 {
				w = strings.TrimPrefix(w, art)
				break
			}
		}
		out = append(out, strings.TrimPrefix(w, "ال"))
	}
	return out
}

// LatinVariants returns up to n alternative spellings of a name to search
// for: other common Latin spellings of its words, and the Latin form of
// Arabic words that appear in the dictionary. The original is not included.
func LatinVariants(name string, n int) []string {
	words := strings.Fields(name)
	if len(words) == 0 || n <= 0 {
		return nil
	}
	type alt struct{ list []string }
	alts := make([]alt, len(words))
	changed := false
	for i, w := range words {
		alts[i].list = []string{w}
		g := groupID(w)
		if g == 0 {
			continue
		}
		var latin []string
		for _, f := range strings.Fields(nameGroups[g-1]) {
			if !isArabic(f) && !strings.EqualFold(f, w) {
				latin = append(latin, strings.ToUpper(f[:1])+f[1:])
			}
		}
		if isArabic(w) && len(latin) > 0 {
			alts[i].list = latin[:min(2, len(latin))]
			changed = true
		} else if len(latin) > 0 {
			alts[i].list = append([]string{w}, latin[:min(2, len(latin))]...)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	var out []string
	seen := map[string]bool{strings.ToLower(name): true}
	for k := 0; k < 3 && len(out) < n; k++ {
		parts := make([]string, len(words))
		for i := range words {
			l := alts[i].list
			parts[i] = l[min(k, len(l)-1)]
		}
		v := strings.Join(parts, " ")
		if !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}
