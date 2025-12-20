#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能合并白名单
- 保留注释行
- 严格去重（只去除完全相同的域名）
"""

def merge_whitelist(local_file, upstream_file, output_file):
    """合并本地和上游白名单"""
    
    # 读取本地白名单
    local_comments = []
    local_domains = set()
    
    try:
        with open(local_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\r\n')
                if not line or line.startswith('#') or line.startswith('!'):
                    local_comments.append(line)
                else:
                    local_domains.add(line.strip())
    except FileNotFoundError:
        pass
    
    # 读取上游白名单
    upstream_comments = []
    upstream_domains = set()
    
    with open(upstream_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or line.startswith('#') or line.startswith('!'):
                upstream_comments.append(line)
            else:
                upstream_domains.add(line.strip())
    
    # 合并域名集合（Set 自动去除完全相同的域名）
    all_domains = local_domains | upstream_domains
    
    # 排序域名（按字母顺序）
    sorted_domains = sorted(all_domains)
    
    # 写入合并后的白名单
    with open(output_file, 'w', encoding='utf-8') as f:
        # 先写入上游注释（保留上游的说明信息）
        for comment in upstream_comments:
            f.write(comment + '\n')
        
        # 如果本地有额外的注释，也保留
        if local_comments:
            f.write('\n# Local additions\n')
            for comment in local_comments:
                if comment not in upstream_comments:
                    f.write(comment + '\n')
        
        # 写入排序后的域名
        if sorted_domains:
            f.write('\n')
            for domain in sorted_domains:
                f.write(domain + '\n')

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 4:
        print("Usage: merge_whitelist.py <local_file> <upstream_file> <output_file>")
        sys.exit(1)
    
    local_file = sys.argv[1]
    upstream_file = sys.argv[2]
    output_file = sys.argv[3]
    
    merge_whitelist(local_file, upstream_file, output_file)
    print(f"✅ Whitelist merged successfully: {output_file}")
