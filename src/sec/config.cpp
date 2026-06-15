// 配置加载与保存实现

#include <sec/config.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>


namespace sec
{

    auto load_config(const std::string &path) -> config
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            return config{};
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

        config cfg;
        const auto err = glz::read<glz::opts{.error_on_unknown_keys = false}>(cfg, content);
        if (err)
        {
            throw std::runtime_error("failed to parse config: " + path);
        }
        return cfg;
    }


    void save_config(const config &cfg, const std::string &path)
    {
        std::string buffer;
        const auto err = glz::write_json(cfg, buffer);
        if (err)
        {
            throw std::runtime_error("failed to serialize config");
        }

        std::ofstream file(path);
        if (!file.is_open())
        {
            throw std::runtime_error("failed to open config for writing: " + path);
        }
        file << buffer;
    }


    auto find_config(const std::vector<std::string> &search_paths,
                     config &cfg) -> std::string
    {
        for (const auto &p : search_paths)
        {
            try
            {
                if (std::filesystem::exists(p))
                {
                    cfg = load_config(p);
                    spdlog::info("Loaded config from: {}", p);
                    return p;
                }
            }
            catch (const std::exception &e)
            {
                spdlog::warn("Failed to parse config {}: {}", p, e.what());
            }
        }
        return {};
    }


    auto user_config_path() -> std::string
    {
#ifdef _WIN32
        auto home = std::getenv("USERPROFILE");
#else
        auto home = std::getenv("HOME");
#endif
        if (home == nullptr) return {};
        namespace fs = std::filesystem;
        return (fs::path{home} / ".spectra" / "spectra.json").string();
    }


    auto ensure_default_config() -> std::string
    {
        auto path = user_config_path();
        if (path.empty()) return {};

        namespace fs = std::filesystem;
        if (fs::exists(path)) return path;

        std::error_code ec;
        fs::create_directories(fs::path{path}.parent_path(), ec);
        if (ec)
        {
            spdlog::warn("Failed to create config directory: {}", ec.message());
            return {};
        }

        auto cfg = config{};
        save_config(cfg, path);
        spdlog::info("Created default config at: {}", path);
        return path;
    }


} // namespace sec
