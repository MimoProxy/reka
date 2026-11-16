import Foundation
import SystemConfiguration

enum NetworkServiceResolver {
    static func activeService() -> String {
        guard let dynamic = SCDynamicStoreCreate(nil, "RekaMac" as CFString, nil, nil),
              let global = SCDynamicStoreCopyValue(dynamic, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let serviceID = global["PrimaryService"] as? String,
              let preferences = SCPreferencesCreate(nil, "RekaMac" as CFString, nil),
              let service = SCNetworkServiceCopy(preferences, serviceID as CFString),
              let name = SCNetworkServiceGetName(service) else { return "Wi-Fi" }
        return name as String
    }
}
