// 配置加载与保存实现

#include <sec/config.hpp>

#include <fstream>
#include <string>
#include <stdexcept>


namespace sec
{

    // 从 JSON 文件加载配置
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
        const auto err = glz::read_json(cfg, content);
        if (err)
        {
            throw std::runtime_error("failed to parse config: " + path);
        }
        return cfg;
    }


    // 将配置序列化为 JSON 并写入文件
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


} // namespace sec
