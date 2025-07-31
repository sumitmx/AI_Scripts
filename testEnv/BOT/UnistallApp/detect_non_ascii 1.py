from charset_normalizer import detect
import argparse

def find_non_ascii_with_charset_normalizer(filename):
    # Detect encoding
    with open(filename, 'rb') as f:
        raw_data = f.read()
        encoding_info = detect(raw_data)
        detected_encoding = encoding_info['encoding']
        confidence = encoding_info['confidence']
    
    print(f"Detected encoding: {detected_encoding} (confidence: {confidence:.2f})")
    
    try:
        # Decode with detected encoding
        content = raw_data.decode(detected_encoding)
        
        non_ascii_chars = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for col_num, char in enumerate(line, 1):
                if ord(char) >= 128:
                    non_ascii_chars.append({
                        'char': char,
                        'unicode': ord(char),
                        'line': line_num,
                        'column': col_num,
                        'context': line[max(0, col_num-10):col_num+10]
                    })
        
        return non_ascii_chars
    
    except Exception as e:
        print(f"Error processing file: {e}")
        return None

def report_non_ascii(filename):
    non_ascii = find_non_ascii_with_charset_normalizer(filename)
    
    if non_ascii is None:
        return
    
    if not non_ascii:
        print(f"✓ All characters in '{filename}' are ASCII")
        return
    
    print(f"\nFound {len(non_ascii)} non-ASCII characters:")
    print("=" * 80)
    
    for char_info in non_ascii:
        print(f"Line {char_info['line']:3d}, Col {char_info['column']:3d}: "
              f"'{char_info['char']}' (U+{char_info['unicode']:04X})")
        print(f"  Context: ...{char_info['context']}...")
        print()

parser = argparse.ArgumentParser(description="Find non-ASCII characters in a file.")
parser.add_argument("-f", "--filename", type=str, help="Path to the file to check for non-ASCII characters.", default="detect_non_ascii.py")
args = parser.parse_args()

if __name__ == "__main__":
    report_non_ascii(args.filename)