
s1 = 'A1234567123456781234567812345678'
s2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'
s3 = 'AC2HX431BG21BE01HUASDZAEP1R3YKFC'
ss = 0x55555555555555555555555555555555
r1 = 0x484437104F14AF17A689B7AC1C0E068B
r2 = 0x75DDE95400521E317BD2289CE781DE6F
r_ = 0xFAA2FBAEDFBAA3C2E3EC40AFCD4D9E43
#print(hex(ss^r1))
#print(hex(ss^r2))
print(hex(ss^r_))
res1 = 0x1D1162451A41FA42F3DCE2F9495B53DE
#print(hex(ss^res1))
res2 = '2088BC0155074B642E877DC9B2D48B3A'
#print(res2[::-1])

