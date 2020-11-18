package work.samosudov.rustlib

import androidx.test.core.app.ApplicationProvider
import org.junit.Before
import org.junit.Test
import work.samosudov.rustlib.crypto.TypeConvert.bytesToLong
import work.samosudov.rustlib.crypto.Utils.*
import java.util.*

class RustAPITest {

    companion object {
        val note = byteArrayOf(1, 49, -56, 16, 72, -122, 103, 46, 68, 17, 99, 117, -96, 105, 117, 0, 0, 0, 0, 0, 76, -96, 22, 106, 90, -59, 124, 1, -55, 48, 96, 10, -60, 49, -63, 1, 15, -41, -72, -75, -104, -57, 42, 47, 3, 54, -24, -65, -62, -52, 77, 14)
        val key = byteArrayOf(69, 121, -20, 127, -124, -3, 114, -88, 7, -102, 47, 22, -12, -31, -92, -93, -41, 62, 32, -6, -80, -24, 115, 22, 115, -83, -91, -43, 98, 103, -54, -15)
    }

    @Before
    fun initNativeLibrary() {
        try {
            RustAPI.init(ApplicationProvider.getApplicationContext())
        } catch (e: Exception) {
            println("RustAPI.init e=${e.message}")
        }
    }

    @Test
    fun testKdf() {
        val res1 = RustAPI.kdfSapling(ByteArray(32), ByteArray(32))
        println("testKdf res1 = ${Arrays.toString(res1)}")
    }

    @Test
    fun testPrfOck() {
        val res1 = RustAPI.prfOck(ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32))
        println("testPrfOck res1 = ${Arrays.toString(res1)}")
//        testPrfOck res1 = [-128, 53, 125, -116, -71, -93, 54, -120, 9, -106, -115, 123, -42, -98, -78, -79, -70, -57, -13, -37, -30, -80, 89, -24, -60, 100, 120, 62, 79, -103, -107, -99]
    }

    @Test
    fun testFullDecrypt() {
        val k = byteArrayOf(2, 50, -105, -8, -98, -12, 80, 68, -16, 86, 70, -122, 101, -56, 30, -69, -24, 98, -29, -89, -126, -103, -113, 123, 120, 54, -104, 20, -124, 125, -39, -51)
        val cipherText = hexToBytes("d59585c9968a30b693f602c3c6edf470f9db660195994c3e7db001b884f70f257211d76f70cbbbfe3540c616ac5cb46fad6f995127f97ba26abac68af7d7003469b88d47176f248895fb4a7c34098044ef8fb6c22df7dac7ac4ab54b6beb68b17fa4ed5799a57e03d5ea044c55901b16cd44fb066c78f4a27094666767c80e355706ae4f38172fdebd92150ab3f2816f521664274c14db625b237dd52845d84c67f10bba2525cf9f1608a3c6e6b0df565108d2f1b61a0a0b7d24320000645863ba6eeba9401504cac3a74c82b03d486d32e424673e6a4e1f747cd79ec8801aef680e59c87a61d0c16a5125eb4f57664e19b33be0e69bd7bff5b5411db9e5993579279b3ef4daa4797ce15a0c4693da8b2e88c3c1027e41a582ecc20b561159b74428938f518a7f121ff00d049ad38ad0bc622ad4885547d0dc726e439f58ec056a786de77a93f4d6395d34aacb84f89861477dc688451afeba065c7f58c6a9cad80fded6030ed1406fef796131b14f683888df9d96c915c00e086b653c3ea6f48075b2bb2b966d5e877c4b58ea06cb12b28fb7562cc9e08995e40b5b064a871f26bb083cbf3bc596d1b3673ab5c80b63448019b7031d28eb7292639dc8e68ead3e395b176bcc4af78f72ca740c3e1fef09af957ed207a71ea147276edf9d20f47cf321fb0feabe3c26bd6b4ba0d74356e1f0195b9640d2b57232426e8ac4533f6efb1d7c3409e6731f83e0fbaed1736af85ba8da53e7cc0d1d6c375fe3530fb06dd692d2f765e0c56449353f2552c3a6dc69954b46533e1c9c4a43d36dc9ceb88c968e97")
        val res1 = RustAPI.fullDecrypt(k, cipherText).drop(52).toByteArray() // 580
        println("testFullDecrypt res1 = ${Arrays.toString(res1)}")
        println("testFullDecrypt res1 text = ${String(res1)}")
    }

    @Test
    fun testEncryptOutgoing() {
        val k = byteArrayOf(2, 50, -105, -8, -98, -12, 80, 68, -16, 86, 70, -122, 101, -56, 30, -69, -24, 98, -29, -89, -126, -103, -113, 123, 120, 54, -104, 20, -124, 125, -39, -51)
        val res1 = RustAPI.encryptOutgoing(k, ByteArray(64))
        println("testFullDecrypt res1 = ${Arrays.toString(res1)}")
    }

    @Test
    fun encryptNp() {
        val res1 = RustAPI.encryptNp(key, note + ByteArray(512))
        println("res1 = ${Arrays.toString(res1)}")
    }

    @Test
    fun testConvertAddress() {
        val expected = byteArrayOf(-68, -62, 86, 122, -85, -75, 57, 69, -45, 77, -87, 75, 103, 10, -92, -49, -51, -104, 53, 83, 112, -120, 102, 1, 93, 43, -47, 41, 120, 106, 100, 100, -31, -20, 53, -21, -89, -30, 46, 80, -78, -110, 63, -47, -4, -17, 78, -58, 121, -16, 24, -114, 38, 69, -81, -46, 56, -65, -66, 55, 102, 75, 90, 120, -103, 37, 109, 78, 35, 90, -25, 60, -31, -71, -74, -97, -74, 89, 47, -105, 103, 85, -101, 63, 85, -72, -66, -10, -112, -122, -85, 70, -86, -60, -31, 69, 11, 77, 124, -8, -16, 23, 115, 3, -27, -98, 94, 94, -66, -28, -114, -93, -64, 22, 54, 70, -125, 59, -66, 56, 103, -7, 94, 48, 61, -79, -98, 58, -75, 16, -94, -4, -10, -66, -22, -76, -73, 60, -72, 73, -83, 115, -74, 7, 78, -92, 39, 1, -111, -24, -67, 125, -50, 67, -68, 108, -72, -89, 14, 118, 100, -54, -126, -62, -53, 45, -85, -9, 101, 9, -116, 31, 30, -107, 1, -98, -10, 85, -52, 62, -53, 107, -8, -82, 100, -89, -91, -3, -39, 76, 59, -127, -38, -125, -5, -9, -39, 102, 10, 43, -93, 59, 57, -2, 69, -37, -33, -105, 42, 41, -79, 51, -30, 22, 127, 30, -86, -15, 59, 7, 85, -98, 82, 110, -37, -90, 39, 20, -101, -126, -127, -98, 118, 113, -41, -27, 3, -66, 93, -34, -118, -27, 80, -84, -118, -100, 7, 6, 107, 55, 39, -34, -128, -118, -99, -93, 40, -66, -84, -66, 52, 103, 90, -90, -45, 9, -84, 121, -98, -109, -46, 117, 97, 58, 20, -16, 85, 77, 97, 49, 68, -23, -82, -5, 73, 22, 65, -87, -50, 12, -64, -99, -75, 103, -52, -11, 71, 7, -80, -77, -46, -63, 106, -31, -53, -33, 83, -58, -48, 79, 55, 21, -79, -75, 13, -34, 101, -18, 40, -71, 85, 62, 2, -73, 21, -23, 126, 63, -8, -87, -24, -74, -72, -72, 41, 80, 87, -102, -24, -34, -76, -37, -21, -24, 43, 81, -50, 1, 41, 74, 62, 117, -19, -34, 65, 69, 68, 92, -59, -107, -83, -10, 66, -93, 107, 98, -119, -60, 92, -33, -33, 83, 26, 39, -51, 122, -43, -69, -31, -43, -19, -60, 5, 97, 111, 115, 57, 100, 1, 26, -61, -114, 74, -89, 12, 20, 36, -13, -92, -47, -124, 11, 91, -89, -120, 107, -126, 9, 48, -115, -9, -111, 90, -3, 116, 32, -114, -47, 47, 26, 105, -18, -58, 97, 23, 24, 33, 89, 80, 118, 114, 36, 107, -119, -94, -118, 2, 68, -54, -16, -124, 127, -74, 8, -54, -54, -99, -55, -3, -87, -26, -87, -109, 91, -38, -72, -33, -37, -39, 122, 79, 76, -79, 118, 41, 50, 93, 60, -7, -44, -53, -34, 76, -74, -50, -2, 6, 57, 0, -14, 109, 55, 99, 87, 105, -108, 81, -38, 49, -39, 99, -83, 45, -75, 31, -21, 6, -30, 96, 96, 39, -74, 30, 53, 67, -40, 81, -114, 44, -62, 93, 71, 46, -90, 117, -65, -52, -85, 8, -30, -117, 75, 91, -68, -98, 21, 98, -18, 110, 103, 97, -109, 28, -109, 20, 81, 55, -38, 107, 117, -127, -63, -114, 57, -1, 53, 120, 71, 25, -73, -38, 57, -7, -110, 25, 83, -42, -13, -89, 17, 127, -68, 50, -50, -113, -83, 68, 75, 64, -7, -89, 60, 11, 65, -126, 41, 63, -81, 95, 0)
        val res = RustAPI.checkConvertAddr("ztestsapling12rc54wchrdvp0tlw096c96fa7uu0546e90jfh74k40lgrsjl7z6a9vf5cgr7fxkf08pdj28d0h2")

        println("res=${Arrays.toString(res)}")
        assert(res.contentEquals(expected))
    }

    @Test
    fun testComputeNf() {
        val ak = "3995b253b7741573de048d032d10df145712b4ea61b7e14b45898c92110ba95e"
        val nk = "a3e49eb2c28afda36a9acb8d8abff3d1f78708b464c71b91893b4a008f56db5b"
        val d =  byteArrayOf(-86, 3, -15, 91, -14, 88, 9, -68, -104, -71, 63)
        val pkd = byteArrayOf(-34, -94, 81, 0, 81, 24, -26, 2, -107, -127, 29, 0, -54, 108, -78, 62, 123, -32, 59, 41, -55, -10, 98, 17, 15, -65, 21, 59, 44, -94, 52, -42)
        val vbytes = byteArrayOf(0, 0, 0, 0, 5, -11, -31, 0)
        val rbytes = byteArrayOf(-67, 48, 39, -22, -34, 65, -92, 123, -109, 12, -112, -1, -124, 54, 60, -76, -5, 92, -33, -50, 90, -69, -128, 72, -108, 94, -71, -98, -59, 110, 104, -127)
        val position = 103677
        val resString = RustAPI.computeNf(
            bytesToHex(d),
            bytesToHex(reverseByteArray(pkd)),
            bytesToLong(vbytes).toString(),
            bytesToHex(rbytes),
            ak,
            nk,
            position.toString()
        )
        println("res1 = $resString")

    }

}