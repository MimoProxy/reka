import Foundation

struct EditableResource: Identifiable {
    let id: String
    let definition: [String: JSONValue]
    let isImported: Bool
    let collection: String
    let profileIndex: Int?
}

struct RuleRecord: Identifiable {
    let id: String
    var definition: [String: JSONValue]
    let origin: String
    let sourceID: String?
    let profileIndex: Int?
    let sourceMarker: Bool
    let editable: Bool
    let movable: Bool
    var number: Int
}
