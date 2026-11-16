import Darwin
import Foundation

enum ProcessResourceSampler {
    static func residentBytes(pid: Int32) -> Int? {
        var info = proc_taskinfo()
        let bytes = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(pid, PROC_PIDTASKINFO, 0, $0, Int32(MemoryLayout<proc_taskinfo>.size))
        }
        guard bytes == MemoryLayout<proc_taskinfo>.size else { return nil }
        return Int(info.pti_resident_size)
    }
}
