package identity

// moreGroups extends the spelling dictionary: more Arabic given names and
// surnames, and international names with their common short forms.
var moreGroups = []string{
	// Arabic given names
	"abdelmoneim abdulmonem abdelmoniem عبدالمنعم", "abdelkarim abdulkarim abdelkrim عبدالكريم", "abdelmalek abdulmalik عبدالملك",
	"abdelwahab abdulwahab عبدالوهاب", "abdelnasser abdulnasser abdelnaser عبدالناصر", "abdelghani abdulghani عبدالغني",
	"abdelhady abdulhadi عبدالهادي", "abdelsalam abdulsalam عبدالسلام", "abdelmohsen abdulmohsen عبدالمحسن", "abdelrazek abdulrazzaq عبدالرازق",
	"abdelaziz abdulaziz abdelazez عبدالعزيز", "abdelkader abdulqader abdelkadir عبدالقادر", "abdelhalim abdulhalim عبدالحليم",
	"mahmoud mahmood محمود", "abdo abdou عبده", "hamdy hamdi حمدي", "hamada hamdah حمادة", "mido mehdi ميدو",
	"moataz moutaz معتز", "moaz muaz معاذ", "mu'tasim mutasem معتصم", "mohab muhab مهاب", "medhat midhat مدحت", "mounir munir منير",
	"nasser nasir ناصر", "naser nasser ناصر", "nashat nashaat نشأت", "nagy naji ناجي", "nagi najy ناجي", "nabeel nabil نبيل",
	"hatem hatim حاتم", "haitham hayetham هيثم", "hisham hesham هشام", "hossam husam حسام", "hamed hamid حامد", "hamza hamzah حمزة",
	"ragab rajab رجب", "ramadan ramadhan رمضان", "ramy rami رامي", "reda rida رضا", "rashad rashid رشاد", "refaat rifaat رفعت",
	"saber sabir صابر", "sabry sabri صبري", "said saeed سعيد", "salah salah صلاح", "salman سلمان", "sami samy سامي", "sameh sameh سامح",
	"sayed sayyed سيد", "shady shadi شادي", "shaker shakir شاكر", "shawky shawqi شوقي", "sobhy subhi صبحي", "tamer tamir تامر",
	"tawfik tawfiq توفيق", "wagdy wajdi وجدي", "wael wail وائل", "yahya yehia يحيى", "yasser yasir ياسر", "younis yunis يونس",
	"zaki zaky زكي", "zakaria zakariya zakariyya زكريا", "zeyad ziad زياد", "walid waleed وليد", "mansour mansur منصور", "marwan merwan مروان",
	"mazen mazin مازن", "moustafa mostafa مصطفى", "mohy muhy محيي", "morad murad مراد", "mosaad mosaed مساعد", "nour noor نور",
	"ola ula علا", "dina deena دينا", "doaa duaa دعاء", "eman iman ايمان", "esraa israa اسراء", "heba hiba هبة", "hend hind هند",
	"huda hoda هدى", "laila layla ليلى", "lamia lamya لمياء", "mai may مي", "marwa marwah مروة", "mona muna منى", "nada nadia ندى",
	"naglaa naglaa نجلاء", "nahla nahla نهلة", "noha nuha نهى", "rania rania رانيا", "reem rim ريم", "rasha rasha رشا", "salma selma سلمى",
	"samar samar سمر", "shaimaa shaima شيماء", "sherine shirin شيرين", "soha suha سها", "suzan susan سوزان", "wafaa wafa وفاء", "yasmine yasmin ياسمين",
	"zeinab zainab زينب", "amal amel امل", "amira ameera اميرة", "aya ayah اية", "basma basma بسمة", "farida farida فريدة", "ghada ghada غادة",
	// common Arabic surnames (shown as written, equivalents across spellings)
	"hassan hasan حسن", "hussein husain حسين", "mahmoud mahmood محمود", "mohamed mohammed محمد", "ibrahim ibraheem ابراهيم",
	"abdelrahman abderrahman عبدالرحمن", "elshazly shazly الشاذلي", "elsayed sayed السيد", "elsherif sherif الشريف", "eltahan tahan الطحان",
	"alharbi harbi الحربي", "alqahtani qahtani القحطاني", "alotaibi otaibi العتيبي", "alghamdi ghamdi الغامدي", "alshehri shehri الشهري",
	// international names and short forms
	"alexandra alex sasha", "alexei alexey alexei aleksei", "andrei andrey", "anna ann anne hannah", "carlos charles carlito",
	"catherine katherine kathryn katarina", "christian christiaan", "daniel danny dan", "dmitri dmitry dmitriy", "elena helen yelena",
	"francesco francis frank franz", "gabriel gabe", "giovanni john johann juan jean ivan", "henry harry hank", "isabella isabel isabelle",
	"jacob jake yakov", "joseph jose josef giuseppe yusuf", "lucas lukas luke luca", "marco marc mark markus marcus", "maria mary marie",
	"mikhail michael michel miguel mikael", "nicolas nicholas nikolai nikola", "pablo paul pavel paolo", "pedro peter pierre pyotr",
	"rafael raphael raffaele", "ricardo richard riccardo", "sergey sergei serge", "stefan stephen steven stefano", "viktor victor vittorio",
	"vladimir vlad volodymyr", "yuri yury george jurgen", "zhang chang", "wang wong", "li lee", "chen chan", "wei way", "lin lim",
}

var _ = func() bool { nameGroups = append(nameGroups, moreGroups...); return true }()
