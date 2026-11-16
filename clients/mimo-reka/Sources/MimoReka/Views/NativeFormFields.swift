import SwiftUI

struct NativeFormFields {
    let fields: Binding<[String: JSONValue]>
    func value(_ path: [String]) -> JSONValue { NativeFieldEditing.value(fields.wrappedValue, path: path) }
    func assign(_ path: [String], _ value: JSONValue?) {
        var copy = fields.wrappedValue
        NativeFieldEditing.set(&copy, path: path, value: value)
        fields.wrappedValue = copy
    }
    func string(_ path: [String], fallback: String = "") -> Binding<String> {
        Binding(get: { value(path).stringValue ?? fallback }, set: { assign(path, $0.isEmpty ? nil : .string($0)) })
    }
    func number(_ path: [String]) -> Binding<String> {
        Binding(get: { value(path).intValue.map(String.init) ?? "" }, set: { text in
            if text.isEmpty { assign(path, nil) } else if let n = Int(text) { assign(path, .number(Double(n))) }
        })
    }
    func bool(_ path: [String], fallback: Bool = false) -> Binding<Bool> {
        Binding(get: { value(path).boolValue ?? fallback }, set: { assign(path, .bool($0)) })
    }
    func list(_ path: [String]) -> Binding<String> {
        Binding(get: { (value(path).arrayValue ?? []).compactMap(\.stringValue).joined(separator: ", ") }, set: { text in
            let values = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            assign(path, values.isEmpty ? nil : .array(values.map(JSONValue.string)))
        })
    }
    func object(_ path: [String]) -> Binding<[String: JSONValue]> {
        Binding(get: { value(path).objectValue ?? [:] }, set: { assign(path, .object($0)) })
    }
    func array(_ path: [String]) -> Binding<[JSONValue]> {
        Binding(get: { value(path).arrayValue ?? [] }, set: { assign(path, .array($0)) })
    }
}

private struct NativePairRow: Identifiable, Equatable {
    let id = UUID()
    var fields: [String: JSONValue]
}

/// Rows are seeded once for this editor, so typing does not replace row identity.
struct NativePairList: View {
    @Binding private var value: [JSONValue]
    let nameKey: String
    let valueKey: String
    let nameTitle: String
    let valueTitle: String
    let secret: Bool
    @State private var rows: [NativePairRow]
    init(value: Binding<[JSONValue]>, nameKey: String = "name", valueKey: String = "value", nameTitle: String = "名称", valueTitle: String = "值", secret: Bool = false) {
        _value = value
        self.nameKey = nameKey; self.valueKey = valueKey
        self.nameTitle = nameTitle; self.valueTitle = valueTitle; self.secret = secret
        _rows = State(initialValue: value.wrappedValue.compactMap(\.objectValue).map { NativePairRow(fields: $0) })
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(rows) { row in
                HStack {
                    TextField(nameTitle, text: binding(row.id, nameKey)).trackField()
                    if secret { SecureField(valueTitle, text: binding(row.id, valueKey)).trackField() }
                    else { TextField(valueTitle, text: binding(row.id, valueKey)).trackField() }
                    Button(role: .destructive) { rows.removeAll { $0.id == row.id } } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless).help("移除此项")
                }
            }
            Button("新增", systemImage: "plus") { rows.append(NativePairRow(fields: [nameKey: .string(""), valueKey: .string("")])) }.controlSize(.small)
        }.onChange(of: rows) { value = rows.map { .object($0.fields) } }
    }
    private func binding(_ id: UUID, _ key: String) -> Binding<String> {
        Binding(get: { rows.first { $0.id == id }?.fields[key]?.stringValue ?? "" }, set: { value in
            if let index = rows.firstIndex(where: { $0.id == id }) { rows[index].fields[key] = .string(value) }
        })
    }
}
