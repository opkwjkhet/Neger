import Foundation

/// Centralized runtime decoding for values that should not appear as readable
/// plaintext in the compiled binary. Each byte uses a position-dependent mask,
/// which also avoids storing a recognizable plain hex/ASCII sequence.
enum ProtectedConfiguration {
    /// Decodes a value protected with a random per-byte mask and a second
    /// position-dependent transform. This avoids embedding the token as a
    /// plaintext string or as a single trivially XORed byte sequence.
    private static func decodeMasked(
        cipher: [UInt8],
        mask: [UInt8],
        checksum: UInt64
    ) -> String {
        guard cipher.count == mask.count else { return "" }
        let bytes = zip(cipher, mask).enumerated().map { index, pair -> UInt8 in
            let position = UInt8(truncatingIfNeeded: (index &* 29) &+ 0x53)
            return (pair.0 &- position) ^ pair.1
        }
        guard let value = String(bytes: bytes, encoding: .utf8) else { return "" }
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return hash == checksum ? value : ""
    }

    private static func decode(_ bytes: [UInt8], seed: UInt8) -> String {
        let decoded = bytes.enumerated().map { index, byte in
            byte ^ (seed &+ UInt8(truncatingIfNeeded: index &* 17))
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    private static func verified(
        _ bytes: [UInt8],
        seed: UInt8,
        checksum: UInt64
    ) -> String {
        let value = decode(bytes, seed: seed)
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return hash == checksum ? value : ""
    }

    static var packageToken: String {
        decodeMasked(
            cipher: [
                58, 251, 219, 215, 84, 83, 11, 18, 208, 113, 117, 27, 34, 237,
                216, 240, 151, 82, 231, 207, 159, 172, 93, 55, 46, 254, 154,
                148, 125, 59, 251, 244, 215, 97, 165, 70
            ],
            mask: [
                151, 224, 41, 114, 187, 4, 77, 150, 223, 40, 113, 186, 3, 76,
                149, 222, 39, 112, 185, 2, 75, 148, 221, 38, 111, 184, 1, 74,
                147, 220, 37, 110, 183, 0, 73, 146
            ],
            checksum: 0xF8FCD5092BB6D2EE
        )
    }

    static var catalogURL: URL? {
        URL(string: verified([
            207, 204, 189, 170, 152, 198, 34, 49, 76, 50, 48, 1, 24, 237,
            250, 213, 193, 166, 247, 139, 139, 105, 101, 94, 77, 63, 25, 11,
            173, 231, 209, 217, 181, 189, 198, 153, 100, 114, 75, 87, 40, 78,
            1, 234, 227
        ], seed: 0xA7, checksum: 0xC8B2C3EE87201EB9))
    }

    static var updateAPIURL: URL {
        URL(string: verified([
            53, 26, 11, 224, 210, 136, 236, 251, 132, 134, 110, 54, 78, 83,
            63, 52, 24, 28, 161, 195, 222, 175, 252, 150, 144, 118, 120, 91,
            22, 19, 58, 2, 26, 196, 246, 217, 168, 187, 204, 199, 52, 38, 18,
            23, 59, 63, 7, 25, 236, 237, 202, 179, 254, 142, 146, 112, 112, 85, 67
        ], seed: 0x5D, checksum: 0x411FC465623DC1A9))!
    }

    static var updateFallbackURL: URL {
        URL(string: verified([
            171, 160, 145, 134, 116, 34, 6, 21, 44, 53, 25, 22, 250, 194,
            159, 161, 188, 137, 218, 95, 118, 70, 94, 0, 50, 5, 20, 231, 176,
            131, 240, 226, 214, 219, 119, 115, 75, 93, 40, 41, 14, 15, 162,
            242, 206, 180, 180, 145, 135
        ], seed: 0xC3, checksum: 0xEAF0544AC60ADCAD))!
    }
}
