# 🛡️ Rule-ATT&CK Mapper (RAM)

An automated framework for mapping SIEM (Security Information and Event Management) rules to MITRE ATT&CK techniques using Large Language Models.

Based on the research paper: [Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs](https://arxiv.org/html/2502.02337v1)

## 🚀 Live Demo

**[Try RAM Live on Streamlit Cloud →](https://your-app-name.streamlit.app)**

## 📋 Features

- **Multi-step Analysis Pipeline**: 6-stage process for comprehensive rule analysis
- **IoC Extraction**: Automatically extracts indicators of compromise from rules
- **Contextual Enhancement**: Retrieves additional context using web search
- **Natural Language Translation**: Converts technical rules to readable descriptions
- **MITRE ATT&CK Mapping**: Maps rules to relevant attack techniques
- **Confidence Scoring**: Provides reasoning and confidence for each mapping
- **Multiple SIEM Support**: Works with Splunk, Elasticsearch, KQL, and more

## 🛠️ Local Installation

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key (free from [Google AI Studio](https://aistudio.google.com/app/apikey))

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ram-framework.git
   cd ram-framework
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Open your browser** to `http://localhost:8501`

## ☁️ Deploy on Streamlit Cloud (Free)

### Step 1: Prepare Your GitHub Repository

1. **Create a new GitHub repository**
2. **Upload these files to your repo:**
   - `app.py` (main application)
   - `requirements.txt` (dependencies)
   - `README.md` (this file)

### Step 2: Deploy on Streamlit Cloud

1. **Go to [share.streamlit.io](https://share.streamlit.io)**
2. **Sign in with GitHub**
3. **Click "New app"**
4. **Fill in the details:**
   - Repository: `yourusername/ram-framework`
   - Branch: `main`
   - Main file path: `app.py`
5. **Click "Deploy"**

### Step 3: Configure API Key

1. **In Streamlit Cloud, go to your app settings**
2. **Add secrets:**
   ```toml
   # .streamlit/secrets.toml (optional - for pre-configured API key)
   GEMINI_API_KEY = "your_api_key_here"
   ```

## 🔑 Getting Your Gemini API Key

1. **Visit [Google AI Studio](https://aistudio.google.com/app/apikey)**
2. **Sign in with your Google account**
3. **Click "Create API key"**
4. **Copy your API key**
5. **Enter it in the RAM application sidebar**

## 📊 How It Works

### The 6-Step RAM Pipeline

1. **IoC Extraction** 🔍
   - Extracts indicators like process names, file paths, IP addresses
   - Uses zero-shot prompting with Gemini

2. **Contextual Information Retrieval** 🌐
   - Searches for additional context about extracted IoCs
   - Uses web search APIs for enhanced understanding

3. **Natural Language Translation** 📝
   - Converts structured SIEM rules to readable descriptions
   - Combines syntactic and semantic information

4. **Data Source Identification** 📋
   - Identifies relevant MITRE ATT&CK data sources
   - Maps to framework components

5. **Probable Technique Recommendation** 🎯
   - Generates list of probable MITRE ATT&CK techniques
   - Uses LLM knowledge of the framework

6. **Relevant Technique Extraction** ✅
   - Filters and scores techniques by relevance
   - Provides reasoning and confidence scores

## 💡 Example SIEM Rules

### Splunk - Suspicious PowerShell
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688 
| search process_name="*powershell.exe*" command_line="*-EncodedCommand*" 
| stats count by host, user, process_name, command_line
```

### Elasticsearch - Network Connections
```json
GET /logs/_search {
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "network"}},
        {"range": {"destination_port": {"gte": 4444, "lte": 4445}}}
      ]
    }
  }
}
```

## 📈 Performance

Based on the original research:
- **Average Recall**: 0.75
- **Average Precision**: 0.52
- **Support**: 670+ MITRE ATT&CK techniques
- **Languages**: Works with multiple SIEM query languages

## 🔧 Customization

### Modify Confidence Threshold
```python
# In app.py, adjust the confidence threshold
confidence_threshold = 0.7  # Default: 0.7 (70%)
```

### Add New SIEM Formats
The framework is designed to work with any SIEM rule format. Simply paste your rule and the LLM will interpret it.

### Extend Context Sources
```python
# Add more context sources in retrieve_contextual_info()
def search_additional_sources(self, query):
    # Add your custom threat intelligence sources
    pass
```

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes**
4. **Submit a pull request**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original research paper authors
- Google for providing the Gemini API
- Streamlit for the amazing framework
- MITRE for the ATT&CK framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/ram-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ram-framework/discussions)
- **Email**: your.email@example.com

## 🔮 Roadmap

- [ ] Support for more LLM providers (OpenAI, Anthropic, etc.)
- [ ] Batch processing for multiple rules
- [ ] Export results to various formats (JSON, CSV, PDF)
- [ ] Integration with SIEM platforms
- [ ] Custom technique databases
- [ ] Advanced visualization of mappings

---

**⭐ Star this repository if you find it useful!**
