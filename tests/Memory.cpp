/**
 * @file Memory.cpp
 * @brief 内存模块测试
 */

#include <sec/memory/container.hpp>
#include <sec/memory/pool.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

using namespace sec::memory;

#define CHECK(cond)                                        \
    do                                                     \
    {                                                      \
        if (!(cond))                                       \
        {                                                  \
            std::cerr << "FAIL: " #cond "\n"               \
                      << "  at " __FILE__ ":" << __LINE__  \
                      << "\n";                             \
            return 1;                                      \
        }                                                  \
    } while (0)

static auto test_current_resource() -> int
{
    auto *mr = current_resource();
    CHECK(mr != nullptr);
    return 0;
}

static auto test_effective_mr() -> int
{
    auto *def_mr = current_resource();
    CHECK(effective_mr(nullptr) == def_mr);
    CHECK(effective_mr(def_mr) == def_mr);
    return 0;
}

static auto test_pmr_string() -> int
{
    string s = "hello spectra";
    CHECK(s == "hello spectra");
    CHECK(s.size() == 13);

    string s2 = s;
    CHECK(s2 == s);

    s2 += " extended";
    CHECK(s2.size() > s.size());
    return 0;
}

static auto test_pmr_vector() -> int
{
    vector<int> v;
    v.push_back(1);
    v.push_back(2);
    v.push_back(3);
    CHECK(v.size() == 3);
    CHECK(v[0] == 1);
    CHECK(v[1] == 2);
    CHECK(v[2] == 3);

    vector<string> vs;
    vs.push_back("alpha");
    vs.push_back("beta");
    CHECK(vs.size() == 2);
    CHECK(vs[0] == "alpha");
    CHECK(vs[1] == "beta");
    return 0;
}

static auto test_pmr_map() -> int
{
    map<int, string> m;
    m[1] = "one";
    m[2] = "two";
    m[3] = "three";
    CHECK(m.size() == 3);
    CHECK(m[1] == "one");
    CHECK(m[2] == "two");
    CHECK(m[3] == "three");
    CHECK(m.count(99) == 0);
    return 0;
}

static auto test_pmr_unordered_map() -> int
{
    unordered_map<string, int> um;
    um["x"] = 10;
    um["y"] = 20;
    CHECK(um.size() == 2);
    CHECK(um["x"] == 10);
    CHECK(um["y"] == 20);
    CHECK(um.count("z") == 0);
    return 0;
}

static auto test_pmr_unordered_set() -> int
{
    unordered_set<string> us;
    us.insert("alpha");
    us.insert("beta");
    us.insert("alpha");
    CHECK(us.size() == 2);
    CHECK(us.count("alpha") == 1);
    CHECK(us.count("beta") == 1);
    CHECK(us.count("gamma") == 0);
    return 0;
}

static auto test_pmr_list() -> int
{
    list<int> l;
    l.push_back(10);
    l.push_back(20);
    l.push_front(5);
    CHECK(l.size() == 3);
    auto it = l.begin();
    CHECK(*it == 5);
    ++it;
    CHECK(*it == 10);
    ++it;
    CHECK(*it == 20);
    return 0;
}

static auto test_pmr_vector_with_custom_mr() -> int
{
    synchronized_pool pool;
    vector<std::uint8_t> buf(&pool);
    for (int i = 0; i < 256; ++i)
    {
        buf.push_back(static_cast<std::uint8_t>(i));
    }
    CHECK(buf.size() == 256);
    CHECK(buf[0] == 0);
    CHECK(buf[255] == 255);
    return 0;
}

static auto test_system_global_pool() -> int
{
    auto *gp = system::global_pool();
    CHECK(gp != nullptr);
    auto *gp2 = system::global_pool();
    CHECK(gp == gp2);
    return 0;
}

static auto test_system_local_pool() -> int
{
    auto *lp = system::local_pool();
    CHECK(lp != nullptr);
    auto *lp2 = system::local_pool();
    CHECK(lp == lp2);
    return 0;
}

static auto test_system_hot_pool() -> int
{
    auto *hp = system::hot_pool();
    CHECK(hp != nullptr);
    CHECK(hp == system::local_pool());
    return 0;
}

static auto test_pooled_object_new_delete() -> int
{
    struct test_obj : public pooled_object<test_obj>
    {
        int value{0};
        explicit test_obj(int v) : value{v} {}
    };

    auto *obj = new test_obj(42);
    CHECK(obj->value == 42);
    delete obj;
    return 0;
}

static auto test_pooled_object_array() -> int
{
    struct test_arr : public pooled_object<test_arr>
    {
        int data{0};
    };

    auto *arr = new test_arr[4];
    for (int i = 0; i < 4; ++i)
    {
        arr[i].data = i;
    }
    CHECK(arr[0].data == 0);
    CHECK(arr[3].data == 3);
    delete[] arr;
    return 0;
}

static auto test_pooled_object_global() -> int
{
    struct global_obj : public pooled_object<global_obj, pool_type::global>
    {
        int x{0};
        explicit global_obj(int v) : x{v} {}
    };

    auto *obj = new global_obj(99);
    CHECK(obj->x == 99);
    delete obj;
    return 0;
}

static auto test_frame_arena() -> int
{
    frame_arena arena;
    auto *mr = arena.get();
    CHECK(mr != nullptr);

    allocator<std::uint8_t> alloc(mr);
    auto *mem = alloc.allocate(64);
    CHECK(mem != nullptr);
    alloc.deallocate(mem, 64);

    arena.reset();
    return 0;
}

static auto test_frame_arena_reuse() -> int
{
    frame_arena arena;

    {
        allocator<int> alloc(arena.get());
        auto *p1 = alloc.allocate(10);
        for (int i = 0; i < 10; ++i)
        {
            p1[i] = i;
        }
        CHECK(p1[5] == 5);
        alloc.deallocate(p1, 10);
    }

    arena.reset();

    {
        allocator<int> alloc(arena.get());
        auto *p2 = alloc.allocate(10);
        CHECK(p2 != nullptr);
        alloc.deallocate(p2, 10);
    }

    return 0;
}

static auto test_monotonic_buffer() -> int
{
    monotonic_buffer mbr;
    allocator<char> alloc(&mbr);
    auto *p = alloc.allocate(32);
    CHECK(p != nullptr);
    mbr.release();
    return 0;
}

static auto test_enable_pooling() -> int
{
    auto *before = current_resource();
    system::enable_pooling();
    auto *after = current_resource();
    CHECK(after == system::global_pool());
    std::pmr::set_default_resource(before);
    return 0;
}

auto main() -> int
{
    int failures = 0;

    if (auto r = test_current_resource(); r) { ++failures; }
    if (auto r = test_effective_mr(); r) { ++failures; }
    if (auto r = test_pmr_string(); r) { ++failures; }
    if (auto r = test_pmr_vector(); r) { ++failures; }
    if (auto r = test_pmr_map(); r) { ++failures; }
    if (auto r = test_pmr_unordered_map(); r) { ++failures; }
    if (auto r = test_pmr_unordered_set(); r) { ++failures; }
    if (auto r = test_pmr_list(); r) { ++failures; }
    if (auto r = test_pmr_vector_with_custom_mr(); r) { ++failures; }
    if (auto r = test_system_global_pool(); r) { ++failures; }
    if (auto r = test_system_local_pool(); r) { ++failures; }
    if (auto r = test_system_hot_pool(); r) { ++failures; }
    if (auto r = test_pooled_object_new_delete(); r) { ++failures; }
    if (auto r = test_pooled_object_array(); r) { ++failures; }
    if (auto r = test_pooled_object_global(); r) { ++failures; }
    if (auto r = test_frame_arena(); r) { ++failures; }
    if (auto r = test_frame_arena_reuse(); r) { ++failures; }
    if (auto r = test_monotonic_buffer(); r) { ++failures; }
    if (auto r = test_enable_pooling(); r) { ++failures; }

    if (failures == 0)
    {
        std::cout << "Memory: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Memory: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
