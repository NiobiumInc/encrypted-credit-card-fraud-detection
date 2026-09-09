// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// timing_summary.h — structured telemetry for CPU/GPU/FPGA benchmarks.
//
// Each benchmark process writes a JSON file capturing:
//   - role / workload / mode / detail (identity)
//   - wall_ms              (process wall, auto-measured by TimingScope)
//   - t_compute_ms         (FHE compute work, user-set)
//   - peak_ram_mb          (VmHWM from /proc/self/status; Linux only, 0 elsewhere)
//   - metadata             (OpenFHE/FIDESlib/CUDA versions, GPU info, hostname)
//
// Single-process workload:
//
//   int main() {
//     nb::TimingSummary ts{.role="harness", .workload="Bootstrap", .mode="GPU"};
//     nb::TimingScope wall(ts);                       // wall_ms set on scope exit
//     auto t0 = std::chrono::high_resolution_clock::now();
//     /* ... FHE compute ... */
//     ts.t_compute_ms = nb::elapsed_ms(t0);
//     nb::write_timing_summary(ts);
//     return 0;
//   }
//
// Multi-process workload: each process picks a unique `role`
// (e.g. "harness", "server", "batch_0003", "reduce"). CI aggregates.

#ifndef NB_TELEMETRY_TIMING_SUMMARY_H
#define NB_TELEMETRY_TIMING_SUMMARY_H

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace nb {

struct TimingSummary {
    std::string role;        // "harness" | "server" | "batch_<idx>" | "reduce"
    std::string workload;    // e.g. "Fraud"
    std::string mode;        // "CPU" | "GPU"
    std::string detail;      // "2x2" | "MEDIUM mono" | "" | ...
    double wall_ms = 0.0;
    double t_compute_ms = 0.0;
    // Optional: strict T_GPU-total per the GPU pipeline diagram (① H2D + ②
    // kernel + ③ D2H), summed across all FHE phases in the workload. Set ONLY
    // for multi-iteration workloads where t_compute_ms uses a
    // wide pipeline span that also includes CPU glue and IO between phases.
    // For single-iteration workloads (Bootstrap, MatMul, MatVec) leave at 0 —
    // t_compute_ms IS strict T_GPU-total for those (single library call, no
    // glue, no IO).
    double t_gpu_total_ms = 0.0;
};

inline double elapsed_ms(std::chrono::high_resolution_clock::time_point t0) {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(now - t0).count();
}

class TimingScope {
public:
    explicit TimingScope(TimingSummary& s)
        : s_(s), t0_(std::chrono::high_resolution_clock::now()) {}
    ~TimingScope() { s_.wall_ms = elapsed_ms(t0_); }
    TimingScope(const TimingScope&) = delete;
    TimingScope& operator=(const TimingScope&) = delete;
private:
    TimingSummary& s_;
    std::chrono::high_resolution_clock::time_point t0_;
};

namespace detail {

inline long read_vmhwm_kb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmHWM:", 0) == 0) {
            std::istringstream iss(line);
            std::string label;
            long kb;
            iss >> label >> kb;
            return kb;
        }
    }
    return 0;
}

inline std::string env_or_empty(const char* key) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : std::string();
}

inline std::string capture_cmd(const std::string& cmd) {
    std::string out;
    FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!p) return out;
    char buf[256];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

inline std::string hostname_str() {
    char h[256] = {0};
    gethostname(h, sizeof(h) - 1);
    return std::string(h);
}

inline std::string utc_timestamp() {
    std::time_t now = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
    return std::string(buf);
}

inline std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char tmp[8];
                    std::snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                    out += tmp;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

inline std::string kv(const std::string& k, const std::string& v) {
    return "\"" + json_escape(k) + "\": \"" + json_escape(v) + "\"";
}

}  // namespace detail

// Writes <NB_TIMING_SUMMARY_DIR>/timing_summary_<role>_<pid>.json (or cwd if env unset).
// Captures peak_ram_mb (VmHWM) and metadata at call time.
inline void write_timing_summary(const TimingSummary& s) {
    using namespace detail;

    const long peak_kb = read_vmhwm_kb();
    const long peak_mb = peak_kb / 1024;

    // Metadata: best-effort, never fails the run.
    const std::string nvidia_query =
        "nvidia-smi --query-gpu=name,compute_cap,driver_version "
        "--format=csv,noheader 2>/dev/null | head -1";
    const std::string gpu_csv = capture_cmd(nvidia_query);
    std::string gpu_name, gpu_cap, gpu_driver;
    {
        // gpu_csv format: "NVIDIA GeForce RTX 5090, 12.0, 580.159.03"
        std::stringstream ss(gpu_csv);
        std::string item;
        if (std::getline(ss, item, ',')) gpu_name = item;
        if (std::getline(ss, item, ',')) gpu_cap = item;
        if (std::getline(ss, item, ',')) gpu_driver = item;
        auto trim = [](std::string& x) {
            while (!x.empty() && x.front() == ' ') x.erase(x.begin());
            while (!x.empty() && x.back() == ' ') x.pop_back();
        };
        trim(gpu_name); trim(gpu_cap); trim(gpu_driver);
    }

    const std::string out_dir = env_or_empty("NB_TIMING_SUMMARY_DIR");
    const std::string dir = out_dir.empty() ? "." : out_dir;

    std::ostringstream path;
    path << dir << "/timing_summary_" << s.role << "_" << getpid() << ".json";

    std::ofstream f(path.str());
    if (!f) {
        std::fprintf(stderr, "[timing_summary] WARN: cannot write %s\n", path.str().c_str());
        return;
    }

    f << "{\n";
    f << "  \"schema_version\": 1,\n";
    f << "  " << kv("role", s.role) << ",\n";
    f << "  " << kv("workload", s.workload) << ",\n";
    f << "  " << kv("mode", s.mode) << ",\n";
    f << "  " << kv("detail", s.detail) << ",\n";
    f << "  \"wall_ms\": "       << s.wall_ms       << ",\n";
    f << "  \"t_compute_ms\": "  << s.t_compute_ms  << ",\n";
    // t_gpu_total_ms is optional: emit as null when unset (single-iter
    // workloads like Bootstrap/MatMul where t_compute_ms IS T_GPU-total),
    // emit the value when set (multi-iteration workloads).
    if (s.t_gpu_total_ms > 0.0) {
        f << "  \"t_gpu_total_ms\": " << s.t_gpu_total_ms << ",\n";
    } else {
        f << "  \"t_gpu_total_ms\": null,\n";
    }
    f << "  \"peak_ram_mb\": "   << peak_mb         << ",\n";
    f << "  \"metadata\": {\n";
    f << "    " << kv("hostname",            hostname_str())                  << ",\n";
    f << "    " << kv("timestamp_utc",       utc_timestamp())                 << ",\n";
    f << "    " << kv("gpu_name",            gpu_name)                        << ",\n";
    f << "    " << kv("gpu_compute_cap",     gpu_cap)                         << ",\n";
    f << "    " << kv("gpu_driver_version",  gpu_driver)                      << ",\n";
    f << "    " << kv("openfhe_version",     env_or_empty("OPENFHE_VERSION"))    << ",\n";
    f << "    " << kv("fideslib_version",    env_or_empty("FIDESLIB_VERSION"))   << ",\n";
    f << "    " << kv("fideslib_commit",     env_or_empty("FIDESLIB_COMMIT"))    << ",\n";
    f << "    " << kv("cuda_runtime",        env_or_empty("CUDA_RUNTIME_VERSION"))<< "\n";
    f << "  }\n";
    f << "}\n";
}

}  // namespace nb

#endif  // NB_TELEMETRY_TIMING_SUMMARY_H
