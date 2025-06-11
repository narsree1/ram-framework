# 🚀 Streamlit Cloud Deployment Guide for RAM

This guide will walk you through deploying the Rule-ATT&CK Mapper (RAM) on Streamlit Cloud for **free**.

## 📋 Prerequisites

- [ ] GitHub account
- [ ] Google Gemini API key ([Get it here](https://aistudio.google.com/app/apikey))
- [ ] Basic knowledge of GitHub

## 🛠️ Step-by-Step Deployment

### Step 1: Get Your Gemini API Key

1. **Visit [Google AI Studio](https://aistudio.google.com/app/apikey)**
2. **Sign in** with your Google account
3. **Click "Create API key"**
4. **Copy and save** your API key securely
   ```
   Example: AIzaSyC...your_api_key_here...XYZ
   ```

### Step 2: Create GitHub Repository

1. **Go to [GitHub.com](https://github.com)** and sign in
2. **Click "New repository"** (green button)
3. **Repository settings:**
   - Repository name: `ram-framework` (or your preferred name)
   - Description: `Rule-ATT&CK Mapper - SIEM to MITRE ATT&CK mapping`
   - Visibility: `Public` (required for free Streamlit Cloud)
   - Initialize: ✅ Add a README file
4. **Click "Create repository"**

### Step 3: Upload Files to GitHub

You need to upload these files to your repository:

#### Required Files Structure:
```
ram-framework/
├── app.py                    # Main application
├── requirements.txt          # Dependencies
├── README.md                 # Documentation
└── .streamlit/
    ├── config.toml           # Streamlit configuration
    └── secrets.toml          # Secrets template (optional)
```

#### Upload Methods:

**Option A: GitHub Web Interface (Easier)**
1. **Click "uploading an existing file"** in your repo
2. **Drag and drop** or **choose files**:
   - Upload `app.py`
   - Upload `requirements.txt`
   - Upload `README.md`
3. **Create `.streamlit` folder:**
   - Click "Create new file"
   - Type `.streamlit/config.toml`
   - Paste the config content
4. **Commit changes**

**Option B: Git Commands (Advanced)**
```bash
git clone https://github.com/yourusername/ram-framework.git
cd ram-framework
# Copy your files here
git add .
git commit -m "Initial RAM deployment"
git push origin main
```

### Step 4: Deploy on Streamlit Cloud

1. **Visit [share.streamlit.io](https://share.streamlit.io)**
2. **Sign in with GitHub**
3. **Click "New app"**
4. **Fill deployment form:**
   ```
   Repository: yourusername/ram-framework
   Branch: main
   Main file path: app.py
   App URL: ram-framework (or custom name)
   ```
5. **Click "Deploy!"**

### Step 5: Configure Secrets (Recommended)

**Option A: Using Streamlit Cloud Secrets (Recommended)**
1. **Go to your app dashboard** on Streamlit Cloud
2. **Click the gear icon** ⚙️ (Settings)
3. **Go to "Secrets" tab**
4. **Add your secrets:**
   ```toml
   CLAUDE_API_KEY = "your_actual_api_key_here"
   
   [settings]
   default_confidence_threshold = 0.7
   max_techniques_display = 5
   ```
5. **Click "Save"**
6. **App will restart automatically**

**Option B: Manual Entry (Alternative)**
- Users can enter API key directly in the app sidebar
- Less secure but works for testing

### Step 6: Test Your Deployment

1. **Wait for deployment** (usually 2-5 minutes)
2. **Click "View app"** or visit your app URL
3. **Test with example SIEM rule:**
   ```spl
   index=main sourcetype="WinEventLog:Security" EventCode=4688 
   | search process_name="*powershell.exe*" command_line="*-EncodedCommand*" 
   | stats count by host, user, process_name, command_line
   ```
4. **Verify all steps work correctly**

## 🔧 Troubleshooting

### Common Issues and Solutions

#### ❌ "ModuleNotFoundError"
**Problem**: Missing dependencies
**Solution**: Check `requirements.txt` has all required packages
```txt
streamlit>=1.28.0
anthropic>=0.34.0
requests>=2.31.0
pandas>=2.0.0
typing-extensions>=4.5.0
```

#### ❌ "API Key Invalid"
**Problem**: Incorrect or expired API key
**Solution**: 
1. Verify API key in Anthropic Console
2. Check secrets configuration
3. Ensure key starts with "sk-ant-api03-"
4. Ensure no extra spaces in key

#### ❌ "App Won't Start"
**Problem**: Code errors
**Solution**: 
1. Check logs in Streamlit Cloud dashboard
2. Verify all files uploaded correctly
3. Test locally first: `streamlit run app.py`

#### ❌ "Rate Limiting"
**Problem**: Too many API calls
**Solution**: 
1. Increase delays in `retrieve_contextual_info()`
2. Reduce number of IoCs processed
3. Wait and retry

### Performance Optimization

#### Speed up Analysis:
```python
# In app.py, modify these settings:
for ioc_value in ioc_values[:2]:  # Reduce from 3 to 2
    # ...
    time.sleep(1.0)  # Increase delay to avoid rate limits
```

#### Reduce API Costs:
```python
# Use fewer probable techniques
probable_techniques = self.recommend_probable_techniques(rule_description, k=7)  # Reduce from 11
```

## 📊 Monitoring Your App

### Streamlit Cloud Dashboard Features:
- **Logs**: View real-time application logs
- **Metrics**: Monitor app usage and performance
- **Secrets**: Manage API keys securely
- **Settings**: Configure deployment options
- **Share**: Get shareable link

### Usage Analytics:
- View visitor count
- Monitor API usage
- Track performance metrics

## 🔄 Updating Your App

### Method 1: GitHub Web Interface
1. **Go to your GitHub repository**
2. **Click on file to edit** (e.g., `app.py`)
3. **Click pencil icon** ✏️ to edit
4. **Make changes**
5. **Commit changes**
6. **App updates automatically** in ~2 minutes

### Method 2: Git Commands
```bash
git pull origin main
# Make your changes
git add .
git commit -m "Update: description of changes"
git push origin main
```

## 🎯 Best Practices

### Security:
- ✅ **Always use Secrets** for API keys
- ✅ **Never commit API keys** to GitHub
- ✅ **Use environment variables** for configuration
- ✅ **Keep repository public** (required for free tier)

### Performance:
- ✅ **Add caching** with `@st.cache_data`
- ✅ **Optimize API calls** with delays
- ✅ **Handle errors gracefully**
- ✅ **Provide user feedback** with progress bars

### User Experience:
- ✅ **Include example SIEM rules**
- ✅ **Provide clear instructions**
- ✅ **Show progress indicators**
- ✅ **Handle edge cases**

## 📈 Scaling Your App

### Free Tier Limits:
- **1 app per account**
- **Public repositories only**
- **Community support only**
- **Shared resources**

### Upgrade Options:
- **Streamlit for Teams**: Multiple private apps
- **Streamlit for Enterprise**: Advanced features
- **Self-hosting**: Full control

## 🎉 Going Live

### Share Your App:
1. **Get your app URL**: `https://your-app-name.streamlit.app`
2. **Share on social media**
3. **Add to your GitHub README**
4. **Submit to Streamlit Gallery**

### Example Share Links:
```markdown
🛡️ **Try RAM Live**: [ram-framework.streamlit.app](https://ram-framework.streamlit.app)

📚 **Source Code**: [github.com/yourusername/ram-framework](https://github.com/yourusername/ram-framework)
```

## 🆘 Getting Help

### Resources:
- **Streamlit Docs**: [docs.streamlit.io](https://docs.streamlit.io)
- **Streamlit Community**: [discuss.streamlit.io](https://discuss.streamlit.io)
- **GitHub Issues**: Create issues in your repository
- **Google AI Docs**: [ai.google.dev](https://ai.google.dev)

### Support Channels:
- **Streamlit Community Forum**
- **GitHub Discussions**
- **Stack Overflow** (tag: streamlit)
- **Discord/Slack Communities**

---

## ✅ Deployment Checklist

Before going live, ensure:

- [ ] All files uploaded to GitHub
- [ ] API key configured in secrets
- [ ] App deploys without errors
- [ ] Test with sample SIEM rules
- [ ] Error handling works
- [ ] Performance is acceptable
- [ ] Documentation is complete
- [ ] Share links are ready

**🎊 Congratulations! Your RAM application is now live on Streamlit Cloud!**
