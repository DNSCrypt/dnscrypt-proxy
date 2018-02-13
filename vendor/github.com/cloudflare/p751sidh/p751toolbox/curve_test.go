package p751toolbox

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Sage script for generating test vectors:
// sage: p = 2^372 * 3^239 - 1; Fp = GF(p)
// sage: R.<x> = Fp[]
// sage: Fp2 = Fp.extension(x^2 + 1, 'i')
// sage: i = Fp2.gen()
// sage: A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
// sage: C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
// sage: E = EllipticCurve(Fp2, [0,A/C,0,1,0])
// sage: X, Y, Z = (8172151271761071554796221948801462094972242987811852753144865524899433583596839357223411088919388342364651632180452081960511516040935428737829624206426287774255114241789158000915683252363913079335550843837650671094705509470594*i + 9326574858039944121604015439381720195556183422719505497448541073272720545047742235526963773359004021838961919129020087515274115525812121436661025030481584576474033630899768377131534320053412545346268645085054880212827284581557, 2381174772709336084066332457520782192315178511983342038392622832616744048226360647551642232950959910067260611740876401494529727990031260499974773548012283808741733925525689114517493995359390158666069816204787133942283380884077*i + 5378956232034228335189697969144556552783858755832284194802470922976054645696324118966333158267442767138528227968841257817537239745277092206433048875637709652271370008564179304718555812947398374153513738054572355903547642836171, 1)
// sage: P = E((X,Y,Z))
// sage: X2, Y2, Z2 = 2*P
// sage: X3, Y3, Z3 = 3*P
// sage: m = 96550223052359874398280314003345143371473380422728857598463622014420884224892

// A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
var curve_A = ExtensionFieldElement{A: Fp751Element{0x8319eb18ca2c435e, 0x3a93beae72cd0267, 0x5e465e1f72fd5a84, 0x8617fa4150aa7272, 0x887da24799d62a13, 0xb079b31b3c7667fe, 0xc4661b150fa14f2e, 0xd4d2b2967bc6efd6, 0x854215a8b7239003, 0x61c5302ccba656c2, 0xf93194a27d6f97a2, 0x1ed9532bca75}, B: Fp751Element{0xb6f541040e8c7db6, 0x99403e7365342e15, 0x457e9cee7c29cced, 0x8ece72dc073b1d67, 0x6e73cef17ad28d28, 0x7aed836ca317472, 0x89e1de9454263b54, 0x745329277aa0071b, 0xf623dfc73bc86b9b, 0xb8e3c1d8a9245882, 0x6ad0b3d317770bec, 0x5b406e8d502b}}

// C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
var curve_C = ExtensionFieldElement{A: Fp751Element{0x4fb2358bbf723107, 0x3a791521ac79e240, 0x283e24ef7c4c922f, 0xc89baa1205e33cc, 0x3031be81cff6fee1, 0xaf7a494a2f6a95c4, 0x248d251eaac83a1d, 0xc122fca1e2550c88, 0xbc0451b11b6cfd3d, 0x9c0a114ab046222c, 0x43b957b32f21f6ea, 0x5b9c87fa61de}, B: Fp751Element{0xacf142afaac15ec6, 0xfd1322a504a071d5, 0x56bb205e10f6c5c6, 0xe204d2849a97b9bd, 0x40b0122202fe7f2e, 0xecf72c6fafacf2cb, 0x45dfc681f869f60a, 0x11814c9aff4af66c, 0x9278b0c4eea54fe7, 0x9a633d5baf7f2e2e, 0x69a329e6f1a05112, 0x1d874ace23e4}}

var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}

// x(P) = 8172151271761071554796221948801462094972242987811852753144865524899433583596839357223411088919388342364651632180452081960511516040935428737829624206426287774255114241789158000915683252363913079335550843837650671094705509470594*i + 9326574858039944121604015439381720195556183422719505497448541073272720545047742235526963773359004021838961919129020087515274115525812121436661025030481584576474033630899768377131534320053412545346268645085054880212827284581557
var affine_xP = ExtensionFieldElement{A: Fp751Element{0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c}, B: Fp751Element{0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1}}

// x([2]P) = 1476586462090705633631615225226507185986710728845281579274759750260315746890216330325246185232948298241128541272709769576682305216876843626191069809810990267291824247158062860010264352034514805065784938198193493333201179504845*i + 3623708673253635214546781153561465284135688791018117615357700171724097420944592557655719832228709144190233454198555848137097153934561706150196041331832421059972652530564323645509890008896574678228045006354394485640545367112224
var affine_xP2 = ExtensionFieldElement{A: Fp751Element{0x2a77afa8576ce979, 0xab1360e69b0aeba0, 0xd79e3e3cbffad660, 0x5fd0175aa10f106b, 0x1800ebafce9fbdbc, 0x228fc9142bdd6166, 0x867cf907314e34c3, 0xa58d18c94c13c31c, 0x699a5bc78b11499f, 0xa29fc29a01f7ccf1, 0x6c69c0c5347eebce, 0x38ecee0cc57}, B: Fp751Element{0x43607fd5f4837da0, 0x560bad4ce27f8f4a, 0x2164927f8495b4dd, 0x621103fdb831a997, 0xad740c4eea7db2db, 0x2cde0442205096cd, 0x2af51a70ede8324e, 0x41a4e680b9f3466, 0x5481f74660b8f476, 0xfcb2f3e656ff4d18, 0x42e3ce0837171acc, 0x44238c30530c}}

// x([3]P) = 9351941061182433396254169746041546943662317734130813745868897924918150043217746763025923323891372857734564353401396667570940585840576256269386471444236630417779544535291208627646172485976486155620044292287052393847140181703665*i + 9010417309438761934687053906541862978676948345305618417255296028956221117900864204687119686555681136336037659036201780543527957809743092793196559099050594959988453765829339642265399496041485088089691808244290286521100323250273
var affine_xP3 = ExtensionFieldElement{A: Fp751Element{0x2096e3f23feca947, 0xf36f635aa4ad8634, 0xdae3b1c6983c5e9a, 0xe08df6c262cb74b4, 0xd2ca4edc37452d3d, 0xfb5f3fe42f500c79, 0x73740aa3abc2b21f, 0xd535fd869f914cca, 0x4a558466823fb67f, 0x3e50a7a0e3bfc715, 0xf43c6da9183a132f, 0x61aca1e1b8b9}, B: Fp751Element{0x1e54ec26ea5077bd, 0x61380572d8769f9a, 0xc615170684f59818, 0x6309c3b93e84ef6e, 0x33c74b1318c3fcd0, 0xfe8d7956835afb14, 0x2d5a7b55423c1ecc, 0x869db67edfafea68, 0x1292632394f0a628, 0x10bba48225bfd141, 0x6466c28b408daba, 0x63cacfdb7c43}}

// m = 96550223052359874398280314003345143371473380422728857598463622014420884224892
var mScalarBytes = [...]uint8{124, 123, 149, 250, 180, 117, 108, 72, 140, 23, 85, 180, 73, 245, 30, 163, 11, 49, 240, 164, 166, 129, 173, 148, 81, 17, 231, 245, 91, 125, 117, 213}

// x([a]P) = 7893578558852400052689739833699289348717964559651707250677393044951777272628231794999463214496545377542328262828965953246725804301238040891993859185944339366910592967840967752138115122568615081881937109746463885908097382992642*i + 8293895847098220389503562888233557012043261770526854885191188476280014204211818299871679993460086974249554528517413590157845430186202704783785316202196966198176323445986064452630594623103149383929503089342736311904030571524837
var affine_xaP = ExtensionFieldElement{A: Fp751Element{0x2112f3c7d7f938bb, 0x704a677f0a4df08f, 0x825370e31fb4ef00, 0xddbf79b7469f902, 0x27640c899ea739fd, 0xfb7b8b19f244108e, 0x546a6679dd3baebc, 0xe9f0ecf398d5265f, 0x223d2b350e75e461, 0x84b322a0b6aff016, 0xfabe426f539f8b39, 0x4507a0604f50}, B: Fp751Element{0xac77737e5618a5fe, 0xf91c0e08c436ca52, 0xd124037bc323533c, 0xc9a772bf52c58b63, 0x3b30c8f38ef6af4d, 0xb9eed160e134f36e, 0x24e3836393b25017, 0xc828be1b11baf1d9, 0x7b7dab585df50e93, 0x1ca3852c618bd8e0, 0x4efa73bcb359fa00, 0x50b6a923c2d4}}

var one = ExtensionFieldElement{A: Fp751Element{0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2}, B: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}

func TestOne(t *testing.T) {
	var tmp ExtensionFieldElement
	tmp.Mul(&one, &affine_xP)
	if !tmp.VartimeEq(&affine_xP) {
		t.Error("Not equal 1")
	}
}

func (P ProjectivePoint) Generate(rand *rand.Rand, size int) reflect.Value {
	f := ExtensionFieldElement{}
	x, _ := f.Generate(rand, size).Interface().(ExtensionFieldElement)
	z, _ := f.Generate(rand, size).Interface().(ExtensionFieldElement)
	return reflect.ValueOf(ProjectivePoint{
		X: x,
		Z: z,
	})
}

func (curve ProjectiveCurveParameters) Generate(rand *rand.Rand, size int) reflect.Value {
	f := ExtensionFieldElement{}
	A, _ := f.Generate(rand, size).Interface().(ExtensionFieldElement)
	C, _ := f.Generate(rand, size).Interface().(ExtensionFieldElement)
	return reflect.ValueOf(ProjectiveCurveParameters{
		A: A,
		C: C,
	})
}

func Test_jInvariant(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	j := curve.JInvariant()
	// Computed using Sage
	// j = 3674553797500778604587777859668542828244523188705960771798425843588160903687122861541242595678107095655647237100722594066610650373491179241544334443939077738732728884873568393760629500307797547379838602108296735640313894560419*i + 3127495302417548295242630557836520229396092255080675419212556702820583041296798857582303163183558315662015469648040494128968509467224910895884358424271180055990446576645240058960358037224785786494172548090318531038910933793845
	known_j := ExtensionFieldElement{
		A: Fp751Element{0xc7a8921c1fb23993, 0xa20aea321327620b, 0xf1caa17ed9676fa8, 0x61b780e6b1a04037, 0x47784af4c24acc7a, 0x83926e2e300b9adf, 0xcd891d56fae5b66, 0x49b66985beb733bc, 0xd4bcd2a473d518f, 0xe242239991abe224, 0xa8af5b20f98672f8, 0x139e4d4e4d98},
		B: Fp751Element{0xb5b52a21f81f359, 0x715e3a865db6d920, 0x9bac2f9d8911978b, 0xef14acd8ac4c1e3d, 0xe81aacd90cfb09c8, 0xaf898288de4a09d9, 0xb85a7fb88c5c4601, 0x2c37c3f1dd303387, 0x7ad3277fe332367c, 0xd4cbee7f25a8e6f8, 0x36eacbe979eaeffa, 0x59eb5a13ac33},
	}

	if !j.VartimeEq(&known_j) {
		t.Error("Computed incorrect j-invariant: found\n", j, "\nexpected\n", known_j)
	}
}

func TestProjectivePointVartimeEq(t *testing.T) {
	xP := ProjectivePoint{X: affine_xP, Z: one}
	xQ := xP
	// Scale xQ, which results in the same projective point
	xQ.X.Mul(&xQ.X, &curve_A)
	xQ.Z.Mul(&xQ.Z, &curve_A)
	if !xQ.VartimeEq(&xP) {
		t.Error("Expected the scaled point to be equal to the original")
	}
}

func TestPointDoubleVersusSage(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	var xP, xQ ProjectivePoint
	xP = ProjectivePoint{X: affine_xP, Z: one}
	affine_xQ := xQ.Pow2k(&curve, &xP, 1).ToAffine()

	if !affine_xQ.VartimeEq(&affine_xP2) {
		t.Error("\nExpected\n", affine_xP2, "\nfound\n", affine_xQ)
	}
}

func TestPointTripleVersusSage(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	var xP, xQ ProjectivePoint
	xP = ProjectivePoint{X: affine_xP, Z: one}
	affine_xQ := xQ.Pow3k(&curve, &xP, 1).ToAffine()

	if !affine_xQ.VartimeEq(&affine_xP3) {
		t.Error("\nExpected\n", affine_xP3, "\nfound\n", affine_xQ)
	}
}

func TestPointPow2kVersusScalarMult(t *testing.T) {
	var xP, xQ, xR ProjectivePoint
	xP = ProjectivePoint{X: affine_xP, Z: one}
	affine_xQ := xQ.Pow2k(&curve, &xP, 5).ToAffine()               // = x([32]P)
	affine_xR := xR.ScalarMult(&curve, &xP, []byte{32}).ToAffine() // = x([32]P)

	if !affine_xQ.VartimeEq(affine_xR) {
		t.Error("\nExpected\n", affine_xQ, "\nfound\n", affine_xR)
	}
}

func TestScalarMultVersusSage(t *testing.T) {
	xP := ProjectivePoint{X: affine_xP, Z: one}
	affine_xQ := xP.ScalarMult(&curve, &xP, mScalarBytes[:]).ToAffine() // = x([m]P)

	if !affine_xaP.VartimeEq(affine_xQ) {
		t.Error("\nExpected\n", affine_xaP, "\nfound\n", affine_xQ)
	}
}

func TestRecoverCurveParameters(t *testing.T) {
	// Created using old public key generation code that output the a value:
	var a = ExtensionFieldElement{A: Fp751Element{0x9331d9c5aaf59ea4, 0xb32b702be4046931, 0xcebb333912ed4d34, 0x5628ce37cd29c7a2, 0xbeac5ed48b7f58e, 0x1fb9d3e281d65b07, 0x9c0cfacc1e195662, 0xae4bce0f6b70f7d9, 0x59e4e63d43fe71a0, 0xef7ce57560cc8615, 0xe44a8fb7901e74e8, 0x69d13c8366d1}, B: Fp751Element{0xf6da1070279ab966, 0xa78fb0ce7268c762, 0x19b40f044a57abfa, 0x7ac8ee6160c0c233, 0x93d4993442947072, 0x757d2b3fa4e44860, 0x73a920f8c4d5257, 0x2031f1b054734037, 0xdefaa1d2406555cd, 0x26f9c70e1496be3d, 0x5b3f335a0a4d0976, 0x13628b2e9c59}}
	var affine_xP = ExtensionFieldElement{A: Fp751Element{0xea6b2d1e2aebb250, 0x35d0b205dc4f6386, 0xb198e93cb1830b8d, 0x3b5b456b496ddcc6, 0x5be3f0d41132c260, 0xce5f188807516a00, 0x54f3e7469ea8866d, 0x33809ef47f36286, 0x6fa45f83eabe1edb, 0x1b3391ae5d19fd86, 0x1e66daf48584af3f, 0xb430c14aaa87}, B: Fp751Element{0x97b41ebc61dcb2ad, 0x80ead31cb932f641, 0x40a940099948b642, 0x2a22fd16cdc7fe84, 0xaabf35b17579667f, 0x76c1d0139feb4032, 0x71467e1e7b1949be, 0x678ca8dadd0d6d81, 0x14445daea9064c66, 0x92d161eab4fa4691, 0x8dfbb01b6b238d36, 0x2e3718434e4e}}
	var affine_xQ = ExtensionFieldElement{A: Fp751Element{0xb055cf0ca1943439, 0xa9ff5de2fa6c69ed, 0x4f2761f934e5730a, 0x61a1dcaa1f94aa4b, 0xce3c8fadfd058543, 0xeac432aaa6701b8e, 0x8491d523093aea8b, 0xba273f9bd92b9b7f, 0xd8f59fd34439bb5a, 0xdc0350261c1fe600, 0x99375ab1eb151311, 0x14d175bbdbc5}, B: Fp751Element{0xffb0ef8c2111a107, 0x55ceca3825991829, 0xdbf8a1ccc075d34b, 0xb8e9187bd85d8494, 0x670aa2d5c34a03b0, 0xef9fe2ed2b064953, 0xc911f5311d645aee, 0xf4411f409e410507, 0x934a0a852d03e1a8, 0xe6274e67ae1ad544, 0x9f4bc563c69a87bc, 0x6f316019681e}}
	var affine_xQmP = ExtensionFieldElement{A: Fp751Element{0x6ffb44306a153779, 0xc0ffef21f2f918f3, 0x196c46d35d77f778, 0x4a73f80452edcfe6, 0x9b00836bce61c67f, 0x387879418d84219e, 0x20700cf9fc1ec5d1, 0x1dfe2356ec64155e, 0xf8b9e33038256b1c, 0xd2aaf2e14bada0f0, 0xb33b226e79a4e313, 0x6be576fad4e5}, B: Fp751Element{0x7db5dbc88e00de34, 0x75cc8cb9f8b6e11e, 0x8c8001c04ebc52ac, 0x67ef6c981a0b5a94, 0xc3654fbe73230738, 0xc6a46ee82983ceca, 0xed1aa61a27ef49f0, 0x17fe5a13b0858fe0, 0x9ae0ca945a4c6b3c, 0x234104a218ad8878, 0xa619627166104394, 0x556a01ff2e7e}}

	var curveParams = RecoverCurveParameters(&affine_xP, &affine_xQ, &affine_xQmP)

	var tmp ExtensionFieldElement
	tmp.Inv(&curveParams.C).Mul(&tmp, &curveParams.A)

	if !tmp.VartimeEq(&a) {
		t.Error("\nExpected\n", a, "\nfound\n", tmp)
	}
}

var threePointLadderInputs = [3]ProjectivePoint{
	// x(P)
	ProjectivePoint{
		X: ExtensionFieldElement{A: Fp751Element{0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c}, B: Fp751Element{0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1}},
		Z: oneExtensionField,
	},
	// x(Q)
	ProjectivePoint{
		X: ExtensionFieldElement{A: Fp751Element{0x2b71a2a93ad1e10e, 0xf0b9842a92cfb333, 0xae17373615a27f5c, 0x3039239f428330c4, 0xa0c4b735ed7dcf98, 0x6e359771ddf6af6a, 0xe986e4cac4584651, 0x8233a2b622d5518, 0xbfd67bf5f06b818b, 0xdffe38d0f5b966a6, 0xa86b36a3272ee00a, 0x193e2ea4f68f}, B: Fp751Element{0x5a0f396459d9d998, 0x479f42250b1b7dda, 0x4016b57e2a15bf75, 0xc59f915203fa3749, 0xd5f90257399cf8da, 0x1fb2dadfd86dcef4, 0x600f20e6429021dc, 0x17e347d380c57581, 0xc1b0d5fa8fe3e440, 0xbcf035330ac20e8, 0x50c2eb5f6a4f03e6, 0x86b7c4571}},
		Z: oneExtensionField,
	},
	// x(P-Q)
	ProjectivePoint{
		X: ExtensionFieldElement{A: Fp751Element{0x4aafa9f378f7b5ff, 0x1172a683aa8eee0, 0xea518d8cbec2c1de, 0xe191bcbb63674557, 0x97bc19637b259011, 0xdbeae5c9f4a2e454, 0x78f64d1b72a42f95, 0xe71cb4ea7e181e54, 0xe4169d4c48543994, 0x6198c2286a98730f, 0xd21d675bbab1afa5, 0x2e7269fce391}, B: Fp751Element{0x23355783ce1d0450, 0x683164cf4ce3d93f, 0xae6d1c4d25970fd8, 0x7807007fb80b48cf, 0xa005a62ec2bbb8a2, 0x6b5649bd016004cb, 0xbb1a13fa1330176b, 0xbf38e51087660461, 0xe577fddc5dd7b930, 0x5f38116f56947cd3, 0x3124f30b98c36fde, 0x4ca9b6e6db37}},
		Z: oneExtensionField,
	},
}

func TestThreePointLadderVersusSage(t *testing.T) {
	var xR ProjectivePoint
	xR.ThreePointLadder(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], mScalarBytes[:])

	affine_xR := xR.ToAffine()

	sageAffine_xR := ExtensionFieldElement{A: Fp751Element{0x729465ba800d4fd5, 0x9398015b59e514a1, 0x1a59dd6be76c748e, 0x1a7db94eb28dd55c, 0x444686e680b1b8ec, 0xcc3d4ace2a2454ff, 0x51d3dab4ec95a419, 0xc3b0f33594acac6a, 0x9598a74e7fd44f8a, 0x4fbf8c638f1c2e37, 0x844e347033052f51, 0x6cd6de3eafcf}, B: Fp751Element{0x85da145412d73430, 0xd83c0e3b66eb3232, 0xd08ff2d453ec1369, 0xa64aaacfdb395b13, 0xe9cba211a20e806e, 0xa4f80b175d937cfc, 0x556ce5c64b1f7937, 0xb59b39ea2b3fdf7a, 0xc2526b869a4196b3, 0x8dad90bca9371750, 0xdfb4a30c9d9147a2, 0x346d2130629b}}

	if !affine_xR.VartimeEq(&sageAffine_xR) {
		t.Error("\nExpected\n", sageAffine_xR, "\nfound\n", affine_xR)
	}
}

func TestPointTripleVersusAddDouble(t *testing.T) {
	tripleEqualsAddDouble := func(curve ProjectiveCurveParameters, P ProjectivePoint) bool {

		cachedParams := curve.cachedParams()
		var P2, P3, P2plusP ProjectivePoint
		P2.Double(&P, &cachedParams) // = x([2]P)
		P3.Triple(&P, &cachedParams) // = x([3]P)
		P2plusP.Add(&P2, &P, &P)     // = x([2]P + P)

		return P3.VartimeEq(&P2plusP)
	}

	if err := quick.Check(tripleEqualsAddDouble, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestScalarMultPrimeFieldAndCoordinateRecoveryVersusSageGeneratedTorsionPoints(t *testing.T) {
	// x((11,...)) = 11
	var x11 = ProjectivePrimeFieldPoint{X: PrimeFieldElement{A: Fp751Element{0x192a73, 0x0, 0x0, 0x0, 0x0, 0xe6f0000000000000, 0x19024ab93916c5c3, 0x1dcd18cf68876318, 0x7d8c830e0c47ba23, 0x3588ea6a9388299a, 0x8259082aa8e3256c, 0x33533f160446}}, Z: onePrimeField}
	// y((11,...)) = oddsqrt(11^3 + 11)
	var y11 = PrimeFieldElement{A: Fp751Element{0xd38a264df57f3c8a, 0x9c0450d25042dcdf, 0xaf1ab7be7bbed0b6, 0xa307981c42b29630, 0x845a7e79e0fa2ecb, 0x7ef77ef732108f55, 0x97b5836751081f0d, 0x59e3d115f5275ff4, 0x9a02736282284916, 0xec39f71196540e99, 0xf8b521b28dcc965a, 0x6af0b9d7f54c}}

	// x((6,...)) = 6
	var x6 = ProjectivePrimeFieldPoint{X: PrimeFieldElement{A: Fp751Element{0xdba10, 0x0, 0x0, 0x0, 0x0, 0x3500000000000000, 0x3714fe4eb8399915, 0xc3a2584753eb43f4, 0xa3151d605c520428, 0xc116cf5232c7c978, 0x49a84d4b8efaf6aa, 0x305731e97514}}, Z: onePrimeField}
	// y((6,...)) = oddsqrt(6^3 + 6)
	var y6 = PrimeFieldElement{A: Fp751Element{0xe4786c67ba55ff3c, 0x6ffa02bcc2a148e0, 0xe1c5d019df326e2a, 0x232148910f712e87, 0x6ade324bee99c196, 0x4372f82c6bb821f3, 0x91a374a15d391ec4, 0x6e98998b110b7c75, 0x2e093f44d4eeb574, 0x33cdd14668840958, 0xb017cea89e353067, 0x6f907085d4b7}}

	// Little-endian bytes of 3^239
	var three239Bytes = [...]byte{235, 142, 138, 135, 159, 84, 104, 201, 62, 110, 199, 124, 63, 161, 177, 89, 169, 109, 135, 190, 110, 125, 134, 233, 132, 128, 116, 37, 203, 69, 80, 43, 86, 104, 198, 173, 123, 249, 9, 41, 225, 192, 113, 31, 84, 93, 254, 6}
	// Little-endian bytes of 2^372
	var two372Bytes = [...]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}

	// E_0 : y^2 = x^3 + x has a = 0, so (a+2)/4 = 1/2
	var aPlus2Over4 = PrimeFieldElement{A: Fp751Element{0x124d6, 0x0, 0x0, 0x0, 0x0, 0xb8e0000000000000, 0x9c8a2434c0aa7287, 0xa206996ca9a378a3, 0x6876280d41a41b52, 0xe903b49f175ce04f, 0xf8511860666d227, 0x4ea07cff6e7f}}

	// Compute x(P_A) = x([3^239](11,...)) and x([3^239 + 1](11,...))
	var xPA, xPAplus11 = ScalarMultPrimeField(&aPlus2Over4, &x11, three239Bytes[:])

	// Compute x(P_B) = x([2^372](6,...)) and x([2^372 + 1](6,...))
	var xPB, xPBplus6 = ScalarMultPrimeField(&aPlus2Over4, &x6, two372Bytes[:])

	// Check that the computed x-coordinates are correct:

	var testAffine_xPA = xPA.ToAffine()
	if !testAffine_xPA.VartimeEq(&Affine_xPA) {
		t.Error("Recomputed x(P_A) incorrectly: found\n", Affine_xPA, "\nexpected\n", testAffine_xPA)
	}

	var testAffine_xPB = xPB.ToAffine()
	if !testAffine_xPB.VartimeEq(&Affine_xPB) {
		t.Error("Recomputed x(P_A) incorrectly: found\n", Affine_xPB, "\nexpected\n", testAffine_xPB)
	}

	// Recover y-coordinates and check that those are correct:
	var invZ_A, invZ_B PrimeFieldElement

	var X_A, Y_A, Z_A = OkeyaSakuraiCoordinateRecovery(&x11.X, &y11, &xPA, &xPAplus11)
	invZ_A.Inv(&Z_A)
	Y_A.Mul(&Y_A, &invZ_A) // = Y_A / Z_A
	X_A.Mul(&X_A, &invZ_A) // = X_A / Z_A
	if !Affine_yPA.VartimeEq(&Y_A) {
		t.Error("Recovered y(P_A) incorrectly: found\n", Y_A, "\nexpected\n", Affine_yPA)
	}
	if !Affine_xPA.VartimeEq(&X_A) {
		t.Error("Recovered x(P_A) incorrectly: found\n", X_A, "\nexpected\n", Affine_xPA)
	}

	var X_B, Y_B, Z_B = OkeyaSakuraiCoordinateRecovery(&x6.X, &y6, &xPB, &xPBplus6)
	invZ_B.Inv(&Z_B)
	Y_B.Mul(&Y_B, &invZ_B) // = Y_B / Z_B
	X_B.Mul(&X_B, &invZ_B) // = X_B / Z_B
	if !Affine_yPB.VartimeEq(&Y_B) {
		t.Error("Recovered y(P_B) incorrectly: found\n", Y_B, "\nexpected\n", Affine_yPB)
	}
	if !Affine_xPB.VartimeEq(&X_B) {
		t.Error("Recovered x(P_B) incorrectly: found\n", X_B, "\nexpected\n", Affine_xPB)
	}
}

func BenchmarkPointAddition(b *testing.B) {
	var xP = ProjectivePoint{X: curve_A, Z: curve_C}
	var xP2, xP3 ProjectivePoint
	cachedParams := curve.cachedParams()
	xP2.Double(&xP, &cachedParams)

	for n := 0; n < b.N; n++ {
		xP3.Add(&xP2, &xP, &xP)
	}
}

func BenchmarkPointDouble(b *testing.B) {
	var xP = ProjectivePoint{X: curve_A, Z: curve_C}
	cachedParams := curve.cachedParams()

	for n := 0; n < b.N; n++ {
		xP.Double(&xP, &cachedParams)
	}
}

func BenchmarkPointTriple(b *testing.B) {
	var xP = ProjectivePoint{X: curve_A, Z: curve_C}
	cachedParams := curve.cachedParams()

	for n := 0; n < b.N; n++ {
		xP.Triple(&xP, &cachedParams)
	}
}

func BenchmarkScalarMult379BitScalar(b *testing.B) {
	var xR ProjectivePoint
	var mScalarBytes = [...]uint8{84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4}

	for n := 0; n < b.N; n++ {
		xR.ScalarMult(&curve, &threePointLadderInputs[0], mScalarBytes[:])
	}
}

func BenchmarkThreePointLadder379BitScalar(b *testing.B) {
	var xR ProjectivePoint
	var mScalarBytes = [...]uint8{84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4}

	for n := 0; n < b.N; n++ {
		xR.ThreePointLadder(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], mScalarBytes[:])
	}
}
