# Stegascan REST API

A high-performance REST API for detecting and analyzing steganography in digital media files.

## Features

- 🔍 **Multi-format Support**: Images, Audio, Video, and Text documents
- 🚀 **Synchronous Processing**: Upload and get instant results
- 📊 **Detailed Analysis**: Comprehensive steganography detection
- 🔐 **Magic Bytes**: Embedded file and polyglot detection
- 📈 **LSB Analysis**: Least Significant Bit steganography detection
- 🎵 **Spectrogram**: Hidden audio message detection
- 🎬 **Video Analysis**: Frame-by-frame suspicious pattern detection

## Quick Start

### Installation

1. Add to your `Cargo.toml` workspace:

```toml
[workspace]
members = ["analyzers", "parsers", "stegascan-api"]
```

2. Build and run:

```bash
cd stegascan-api
cargo run --release
```

The API will start on `http://localhost:3000` (or 3001 if 3000 is busy)

## API Endpoint

### Scan File

Upload a file and get complete analysis results.

```bash
POST /api/scan
Content-Type: multipart/form-data

file: <binary data>
video_sample_rate: 30 (optional, for video files)
```

**Example with cURL:**
```bash
curl -X POST http://localhost:3001/api/scan \
  -F "file=@suspicious_image.png"
```

**Example with video (custom sample rate):**
```bash
curl -X POST http://localhost:3001/api/scan \
  -F "file=@test_video.mp4" \
  -F "video_sample_rate=60"
```

**Response:**
```json
{
  "file_info": {
    "path": "/tmp/...",
    "size_bytes": 524288,
    "detected_type": "Image",
    "extension": "png"
  },
  "magic_bytes_analysis": {
    "primary_format": "PNG image",
    "has_multiple_formats": true,
    "has_suspicious_data": true,
    "total_signatures_found": 3,
    "format_summary": {
      "images": 2,
      "audio": 0,
      "video": 0,
      "text_documents": 0,
      "archives": 0,
      "executables": 0,
      "other": 1
    },
    "embedded_files": [
      {
        "offset": 4660,
        "offset_hex": "0x1234",
        "description": "JPEG image",
        "file_type": "Image",
        "confidence": "high"
      }
    ],
    "suspicious_findings": [
      "Multiple file signatures detected",
      "Complete file signature found at offset 0x1234: JPEG image"
    ]
  },
  "format_specific_analysis": {
    "type": "Image",
    "exif_metadata": {
      "fields_found": 15,
      "has_thumbnail": true,
      "thumbnail_size_bytes": 8192,
      "comment_fields": [
        "UserComment: Sample comment"
      ],
      "suspicious_fields": [
        "UserComment: potential encoded data"
      ],
      "metadata": [
        {
          "key": "Make",
          "value": "Canon"
        }
      ]
    },
    "lsb_analysis": {
      "is_suspicious": true,
      "channels": [
        {
          "channel_name": "Red",
          "chi_square_score": 125.4,
          "entropy_score": 0.92
        },
        {
          "channel_name": "Green",
          "chi_square_score": 98.2,
          "entropy_score": 0.88
        },
        {
          "channel_name": "Blue",
          "chi_square_score": 110.5,
          "entropy_score": 0.91
        }
      ]
    },
    "dimensions": {
      "width": 1920,
      "height": 1080
    }
  },
  "summary": {
    "steganography_detected": true,
    "confidence_level": "high",
    "threat_indicators": [
      "Suspicious data in file structure",
      "Multiple file formats detected",
      "LSB analysis indicates hidden data",
      "Suspicious EXIF metadata found"
    ],
    "recommendations": [
      "Further investigation recommended",
      "Consider specialized tools",
      "Verify file source"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Response Structure

### File Types

The API automatically detects and analyzes different file types:

#### **Image Analysis**
```json
{
  "type": "Image",
  "exif_metadata": { ... },
  "lsb_analysis": { ... },
  "dimensions": { "width": 1920, "height": 1080 }
}
```

#### **Audio Analysis**
```json
{
  "type": "Audio",
  "sample_count": 1323000,
  "id3_analysis": {
    "title": "Song Title",
    "artist": "Artist Name",
    "suspicious_frames": ["Large comment field: 2048 bytes"]
  },
  "spectrogram_analysis": {
    "high_frequency_energy": 0.15,
    "hidden_message_detected": true,
    "suspicious_patterns": ["Persistent high-frequency tone detected"]
  }
}
```

#### **Video Analysis**
```json
{
  "type": "Video",
  "frames_processed": 1800,
  "errors_encountered": 0,
  "suspicious_frames": [30, 90, 150]
}
```

#### **Text Analysis**
```json
{
  "type": "Text",
  "file_type": "PDF",
  "line_count": 150,
  "word_count": 2500,
  "character_count": 15000,
  "size_bytes": 102400
}
```

## Usage Examples

### Python Client

```python
import requests

# Scan an image
with open('suspicious.png', 'rb') as f:
    response = requests.post(
        'http://localhost:3001/api/scan',
        files={'file': f}
    )
    result = response.json()
    
    print(f"Detected type: {result['file_info']['detected_type']}")
    print(f"Steganography detected: {result['summary']['steganography_detected']}")
    print(f"Confidence: {result['summary']['confidence_level']}")
    
    if result['summary']['threat_indicators']:
        print("\nThreat indicators:")
        for indicator in result['summary']['threat_indicators']:
            print(f"  - {indicator}")

# Scan a video with custom sample rate
with open('test.mp4', 'rb') as f:
    response = requests.post(
        'http://localhost:3001/api/scan',
        files={'file': f},
        data={'video_sample_rate': '60'}
    )
    result = response.json()
    
    if result['format_specific_analysis']['type'] == 'Video':
        video_analysis = result['format_specific_analysis']
        print(f"Frames processed: {video_analysis['frames_processed']}")
        print(f"Suspicious frames: {video_analysis['suspicious_frames']}")
```

### JavaScript Client

```javascript
// Scan a file
async function scanFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch('http://localhost:3001/api/scan', {
    method: 'POST',
    body: formData
  });
  
  const result = await response.json();
  
  console.log('Analysis result:', result);
  console.log('Steganography detected:', result.summary.steganography_detected);
  console.log('Confidence:', result.summary.confidence_level);
  
  return result;
}

// Usage with file input
document.getElementById('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (file) {
    const result = await scanFile(file);
    displayResults(result);
  }
});
```

### Bash Script

```bash
#!/bin/bash

# Scan a single file
scan_file() {
    local file=$1
    echo "Scanning: $file"
    
    curl -X POST http://localhost:3001/api/scan \
        -F "file=@$file" \
        -H "Accept: application/json" \
        | jq '.summary'
}

# Scan multiple files
for file in images/*.png; do
    scan_file "$file"
    echo "---"
done
```

## Performance

- **Images (1080p)**: ~1-2 seconds
- **Audio (3 min)**: ~3-5 seconds
- **Video (1 min)**: ~30 seconds (sample_rate=30)
- **Text/PDF**: ~500ms-2 seconds

## Configuration

### Video Sample Rate

Control video analysis thoroughness:

```bash
# Analyze every 30th frame (faster)
curl -X POST http://localhost:3001/api/scan \
  -F "file=@video.mp4" \
  -F "video_sample_rate=30"

# Analyze every 10th frame (more thorough)
curl -X POST http://localhost:3001/api/scan \
  -F "file=@video.mp4" \
  -F "video_sample_rate=10"
```

### Logging

Set log level with `RUST_LOG`:

```bash
# Debug level
RUST_LOG=debug cargo run

# Info level (default)
RUST_LOG=info cargo run

# Errors only
RUST_LOG=error cargo run
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Analysis successful
- `400 Bad Request`: Missing or invalid file
- `422 Unprocessable Entity`: Analysis failed
- `500 Internal Server Error`: Server error

**Error Response Example:**
```json
{
  "error": "Missing file in request",
  "status": 400
}
```

## Production Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p stegascan-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libssl3 ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/*
    
COPY --from=builder /app/target/release/stegascan-api /usr/local/bin/
EXPOSE 3000
CMD ["stegascan-api"]
```

Build and run:
```bash
docker build -t stegascan-api .
docker run -p 3000:3000 stegascan-api
```

### Production Recommendations

1. **Add authentication**: JWT or API keys
2. **Set file size limits**: Prevent abuse
3. **Add rate limiting**: Per IP or API key
4. **Use reverse proxy**: Nginx or Caddy
5. **Configure CORS**: Specific origins only
6. **Add monitoring**: Prometheus/Grafana
7. **Set up logging**: Structured JSON logs
8. **Use environment variables**: For configuration

## License

MIT License - see LICENSE file for details
