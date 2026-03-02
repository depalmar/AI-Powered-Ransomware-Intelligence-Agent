# 🛡️ Mock Ransomware API Server

This directory contains a lightweight Python server that mimics the `ransomware.live` API. 

It is designed for **demos, webinars, and testing** where you need:
1.  **Predictable Data:** Ensures the output report always looks exactly like the "Golden Sample".
2.  **Offline Capability:** Run the workflow without internet access.
3.  **Safety:** Zero chance of pulling in offensive/graphic content from live leak sites during a presentation.

## 🚀 Usage

No dependencies required. Uses standard Python libraries.

```bash
python mock_api/server.py
```

The server will start on port **3000**.

## 🔗 Endpoints

*   `GET http://localhost:3000/v2/recentvictims`
    *   Returns 24 victims (LockBit 3.0, Play, BlackBasta) matched to the sample report.
*   `GET http://localhost:3000/v2/groups/{group_name}`
    *   Returns static profiles for `lockbit3`, `play`, and `blackbasta`.

## ⚙️ Configuring n8n

To use this mock server in your n8n workflow:

1.  Open the **Fetch Recent Victims** node.
2.  Change URL from `https://api.ransomware.live/v2/recentvictims` to `http://localhost:3000/v2/recentvictims`.
3.  Open the **Get Group Profile** node.
4.  Change URL from `https://api.ransomware.live/v2/groups/{{ $json.group }}` to `http://localhost:3000/v2/groups/{{ $json.group }}`.
