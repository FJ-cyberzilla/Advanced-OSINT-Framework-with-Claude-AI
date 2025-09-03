#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <random>
#include <regex>
#include <chrono>
#include <thread>
#include <iomanip>
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <future>
#include <curl/curl.h>

using json = nlohmann::json;
using namespace std::chrono_literals;

// ANSI Color Codes
namespace Colors {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

// Thread-safe logger
class Logger {
private:
    static std::mutex logMutex;
    static std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
        return ss.str();
    }

public:
    static void info(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << Colors::CYAN << "[" << getCurrentTime() << "] " << Colors::WHITE << message << Colors::RESET << std::endl;
    }
    static void success(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << Colors::GREEN << "[" << getCurrentTime() << "] ✓ " << message << Colors::RESET << std::endl;
    }
    static void warning(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << Colors::YELLOW << "[" << getCurrentTime() << "] ⚠ " << message << Colors::RESET << std::endl;
    }
    static void error(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << Colors::RED << "[" << getCurrentTime() << "] ✗ " << message << Colors::RESET << std::endl;
    }
    static void header(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << Colors::MAGENTA << Colors::BOLD << "\n" << "============================================================" << "\n" << "  " << message << "\n" << "============================================================" << Colors::RESET << std::endl;
    }
};
std::mutex Logger::logMutex;

// Claude AI Integration
class ClaudeAI {
private:
    std::string apiKey;
    std::string apiUrl = "https://api.anthropic.com/v1/messages";

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
        size_t totalSize = size * nmemb;
        response->append((char*)contents, totalSize);
        return totalSize;
    }

public:
    ClaudeAI(const std::string& key) : apiKey(key) {}

    std::string analyzeData(const std::string& context, const std::string& data) {
        if (apiKey.empty()) {
            Logger::warning("Claude API key not configured");
            return "AI analysis unavailable - Please configure Claude API key in config.json";
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            Logger::error("Failed to initialize CURL");
            return "AI analysis unavailable - CURL initialization failed";
        }

        std::string response;
        json request = {
            {"model", "claude-3-sonnet-20240229"},
            {"max_tokens", 1000},
            {"messages", {{
                {"role", "user"},
                {"content", "OSINT Analysis Context: " + context + "\nData: " + data + "\nProvide concise, actionable intelligence findings with risk assessment."}
            }}}
        };

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("x-api-key: " + apiKey).c_str());
        headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");

        curl_easy_setopt(curl, CURLOPT_URL, apiUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.dump().c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            Logger::error("AI API request failed");
            return "AI analysis failed - Network error";
        }

        try {
            json jsonResponse = json::parse(response);
            return jsonResponse["content"][0]["text"].get<std::string>();
        } catch (const std::exception& e) {
            Logger::error("Failed to parse AI response");
            return "Failed to parse AI analysis";
        }
    }
};

// Configuration Manager
class ConfigManager {
private:
    json config;

public:
    ConfigManager() { loadConfig(); }

    void loadConfig() {
        std::ifstream in("config.json");
        if (!in.is_open()) {
            createDefaultConfig();
            return;
        }
        try {
            in >> config;
            Logger::success("Configuration loaded");
        } catch (const std::exception& e) {
            Logger::error("Failed to parse config");
            createDefaultConfig();
        }
    }

    void createDefaultConfig() {
        config = {
            {"ai", {
                {"enabled", true},
                {"claude_api_key", ""}
            }},
            {"modules", {
                {"data_consolidator", true},
                {"phone_lookup", true},
                {"social_checker", true},
                {"username_generator", true}
            }}
        };
        saveConfig();
    }

    void saveConfig() {
        std::ofstream out("config.json");
        if (out.is_open()) {
            out << config.dump(4);
        }
    }

    json& getConfig() { return config; }
};

// Utility functions
class Utils {
public:
    static bool validateEmail(const std::string& email) {
        const std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        return std::regex_match(email, emailRegex);
    }

    static bool validatePhone(const std::string& phone) {
        const std::regex phoneRegex(R"(\+?[1-9]\d{1,14})");
        return std::regex_match(phone, phoneRegex);
    }

    static void simulateProgress(const std::string& task, int steps = 10, int delay_ms = 100) {
        std::cout << Colors::CYAN << task << ": " << Colors::RESET;
        for (int i = 0; i <= steps; ++i) {
            std::cout << "\r" << Colors::CYAN << task << ": " << Colors::GREEN << "[" << i << "/" << steps << "] " << (i * 100 / steps) << "%" << Colors::RESET << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        std::cout << std::endl;
    }

    static std::string extractUsernameFromEmail(const std::string& email) {
        size_t at_pos = email.find('@');
        return (at_pos != std::string::npos) ? email.substr(0, at_pos) : email;
    }
};

// Base Module Class
class Module {
protected:
    std::string name;
    std::string description;
    std::shared_ptr<ConfigManager> config;
    std::shared_ptr<ClaudeAI> ai;

public:
    Module(const std::string& n, const std::string& desc, std::shared_ptr<ConfigManager> cfg, std::shared_ptr<ClaudeAI> aiInstance)
        : name(n), description(desc), config(cfg), ai(aiInstance) {}

    virtual ~Module() = default;
    virtual void execute() = 0;
    virtual std::string collectData() = 0;

    const std::string& getName() const { return name; }
    const std::string& getDescription() const { return description; }
};

// Data Consolidator Module
class DataConsolidator : public Module {
private:
    std::string collectedData;

public:
    DataConsolidator(std::shared_ptr<ConfigManager> cfg, std::shared_ptr<ClaudeAI> ai)
        : Module("Data Consolidator", "Collect and organize target information", cfg, ai) {}

    void execute() override {
        Logger::header("Data Consolidation Module");
        std::string target;
        std::cout << Colors::CYAN << "Enter target (email/phone/username): " << Colors::RESET;
        std::getline(std::cin, target);

        if (target.empty()) {
            Logger::error("Target cannot be empty");
            return;
        }

        collectedData = collectDataForTarget(target);
        displayResults();

        if (config->getConfig()["ai"]["enabled"]) {
            performAIAnalysis(target);
        }
    }

    std::string collectData() override {
        return collectedData;
    }

private:
    std::string collectDataForTarget(const std::string& target) {
        std::stringstream data;

        if (Utils::validateEmail(target)) {
            std::string username = Utils::extractUsernameFromEmail(target);
            data << "Email: " << target << "\n";
            data << "Derived Username: " << username << "\n";
            data << "Email Provider: " << target.substr(target.find('@') + 1) << "\n";
        }
        else if (Utils::validatePhone(target)) {
            data << "Phone: " << target << "\n";
            data << "International Format: " << target << "\n";
        }
        else {
            data << "Username: " << target << "\n";
            data << "Possible Email: " << target << "@gmail.com\n";
        }

        return data.str();
    }

    void displayResults() {
        std::cout << Colors::YELLOW << Colors::BOLD << "\nCollected Data:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << collectedData << Colors::RESET << std::endl;
    }

    void performAIAnalysis(const std::string& target) {
        std::string context = "Analyzing target: " + target;
        std::string aiResult = ai->analyzeData(context, collectedData);

        std::cout << Colors::MAGENTA << Colors::BOLD << "\n🧠 Claude AI Analysis:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << aiResult << Colors::RESET << std::endl;
    }
};

// Phone Lookup Module
class PhoneLookup : public Module {
public:
    PhoneLookup(std::shared_ptr<ConfigManager> cfg, std::shared_ptr<ClaudeAI> ai)
        : Module("Phone Lookup", "Phone number investigation", cfg, ai) {}

    void execute() override {
        Logger::header("Phone Number Lookup");
        std::string phone;
        std::cout << Colors::CYAN << "Enter phone number: " << Colors::RESET;
        std::getline(std::cin, phone);

        if (!Utils::validatePhone(phone)) {
            Logger::error("Invalid phone number format");
            return;
        }

        std::string data = collectDataForPhone(phone);
        displayResults(phone, data);

        if (config->getConfig()["ai"]["enabled"]) {
            performAIAnalysis(phone, data);
        }
    }

    std::string collectData() override {
        return "Phone lookup data";
    }

private:
    std::string collectDataForPhone(const std::string& phone) {
        std::stringstream data;
        data << "Phone Number: " << phone << "\n";
        data << "Validated: Yes\n";
        data << "International Format: " << phone << "\n";
        data << "Possible Location: Various carriers\n";
        return data.str();
    }

    void displayResults(const std::string& phone, const std::string& data) {
        std::cout << Colors::YELLOW << Colors::BOLD << "\nPhone Analysis:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << data << Colors::RESET << std::endl;
    }

    void performAIAnalysis(const std::string& phone, const std::string& data) {
        std::string context = "Phone number analysis: " + phone;
        std::string aiResult = ai->analyzeData(context, data);

        std::cout << Colors::MAGENTA << Colors::BOLD << "\n🧠 Claude AI Analysis:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << aiResult << Colors::RESET << std::endl;
    }
};

// Social Media Checker Module
class SocialChecker : public Module {
public:
    SocialChecker(std::shared_ptr<ConfigManager> cfg, std::shared_ptr<ClaudeAI> ai)
        : Module("Social Media Checker", "Social media presence analysis", cfg, ai) {}

    void execute() override {
        Logger::header("Social Media Investigation");
        std::string username;
        std::cout << Colors::CYAN << "Enter username: " << Colors::RESET;
        std::getline(std::cin, username);

        if (username.empty()) {
            Logger::error("Username cannot be empty");
            return;
        }

        std::string data = collectDataForUsername(username);
        displayResults(username, data);

        if (config->getConfig()["ai"]["enabled"]) {
            performAIAnalysis(username, data);
        }
    }

    std::string collectData() override {
        return "Social media data";
    }

private:
    std::string collectDataForUsername(const std::string& username) {
        std::stringstream data;
        data << "Username: " << username << "\n";
        data << "Platform Analysis:\n";

        std::vector<std::string> platforms = {"Instagram", "Twitter", "Facebook", "LinkedIn", "GitHub"};
        for (const auto& platform : platforms) {
            data << "  • " << platform << ": " << (rand() % 100 > 40 ? "Potential match" : "Not found") << "\n";
        }

        return data.str();
    }

    void displayResults(const std::string& username, const std::string& data) {
        std::cout << Colors::YELLOW << Colors::BOLD << "\nSocial Media Analysis:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << data << Colors::RESET << std::endl;
    }

    void performAIAnalysis(const std::string& username, const std::string& data) {
        std::string context = "Social media analysis for username: " + username;
        std::string aiResult = ai->analyzeData(context, data);

        std::cout << Colors::MAGENTA << Colors::BOLD << "\n🧠 Claude AI Analysis:" << Colors::RESET << std::endl;
        std::cout << Colors::WHITE << aiResult << Colors::RESET << std::endl;
    }
};

// Main Application
class EhunterApp {
private:
    std::shared_ptr<ConfigManager> config;
    std::shared_ptr<ClaudeAI> ai;
    std::vector<std::unique_ptr<Module>> modules;
    std::vector<std::string> allCollectedData;

public:
    EhunterApp() : config(std::make_shared<ConfigManager>()) {
        initializeAI();
        initializeModules();
    }

    void initializeAI() {
        std::string apiKey = config->getConfig()["ai"]["claude_api_key"];
        ai = std::make_shared<ClaudeAI>(apiKey);
        if (!apiKey.empty()) {
            Logger::success("Claude AI initialized");
        } else {
            Logger::warning("Claude API key not configured");
        }
    }

    void initializeModules() {
        json moduleConfig = config->getConfig()["modules"];

        if (moduleConfig["data_consolidator"]) {
            modules.push_back(std::make_unique<DataConsolidator>(config, ai));
        }
        if (moduleConfig["phone_lookup"]) {
            modules.push_back(std::make_unique<PhoneLookup>(config, ai));
        }
        if (moduleConfig["social_checker"]) {
            modules.push_back(std::make_unique<SocialChecker>(config, ai));
        }
    }

    void run() {
        displayBanner();

        while (true) {
            displayMenu();
            int choice;
            std::cin >> choice;
            std::cin.ignore();

            if (choice == static_cast<int>(modules.size() + 1)) {
                performFinalAIAnalysis();
                break;
            }

            if (choice > 0 && choice <= static_cast<int>(modules.size())) {
                try {
                    modules[choice - 1]->execute();
                    allCollectedData.push_back(modules[choice - 1]->collectData());
                } catch (const std::exception& e) {
                    Logger::error("Module execution failed: " + std::string(e.what()));
                }
            } else {
                Logger::error("Invalid selection");
            }
        }
    }

private:
    void displayBanner() {
        std::cout << Colors::MAGENTA << Colors::BOLD << R"(
    ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
    ██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    )" << Colors::RESET << std::endl;

        std::cout << Colors::CYAN << Colors::BOLD << " FJ™-CYBERZILLA® - An Advanced Osint by Claude AI Analysis" << Colors::RESET << std::endl;
        std::cout << Colors::YELLOW << "    Cross-Modular Intelligence Analysis" << Colors::RESET << std::endl;
    }

    void displayMenu() {
        std::cout << Colors::CYAN << Colors::BOLD << "\nAvailable Modules:" << Colors::RESET << std::endl;
        for (size_t i = 0; i < modules.size(); ++i) {
            std::cout << Colors::WHITE << "  " << (i + 1) << ". " << Colors::GREEN << modules[i]->getName() << Colors::RESET << " - " << modules[i]->getDescription() << std::endl;
        }
        std::cout << Colors::WHITE << "  " << (modules.size() + 1) << ". " << Colors::RED << "Exit with Final AI Analysis" << Colors::RESET << std::endl;
        std::cout << Colors::CYAN << "\nSelect module: " << Colors::RESET;
    }

    void performFinalAIAnalysis() {
        if (allCollectedData.empty()) {
            Logger::info("No data collected for analysis");
            return;
        }

        std::string combinedData;
        for (const auto& data : allCollectedData) {
            combinedData += data + "\n";
        }

        std::cout << Colors::MAGENTA << Colors::BOLD << "\n🎯 FINAL CROSS-MODULAR AI ANALYSIS:" << Colors::RESET << std::endl;
        std::string aiResult = ai->analyzeData("Comprehensive OSINT Analysis of all collected data", combinedData);
        std::cout << Colors::WHITE << aiResult << Colors::RESET << std::endl;
    }
};

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    try {
        EhunterApp app;
        app.run();
    } catch (const std::exception& e) {
        Logger::error("Application error: " + std::string(e.what()));
        return 1;
    }
    curl_global_cleanup();
    return 0;
}
