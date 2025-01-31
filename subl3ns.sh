#!/bin/bash
set -eo pipefail
bold="\e[1m"
underlined="\e[4m"
red="\e[31m"
green="\e[32m"
blue="\e[34m"
cyan="\e[36m"
end="\e[0m"
VERSION="2023-10-01"
PRG=${0##*/}
# Banner
echo -e "${cyan}

                                  \`~xu1v~\`   
                               -?Zhv~~|o66x  
                            !LADB8}x^=,_<KEV 
          \`,*}VJVL!     \`!zON8B##QnnYLL(,;dD~
        _xhKKdQAJzPD\".~LhQB#Q####@dnnlYv;>dN_
       !aKKKqb8DbO8#dPAdEQ######@@@BqV}LlAq! 
       wKSddPnvrKB@@\$REDN\$Q#@@@#B8Oqen(<!-   
       VRWjn(r!vZ8Q#Qhrr^|h#a>\`              
      .}scvv*|?~***(*~=\\\`V\$BBo               
     ,}m6W6sLr?r^Lyv=}nv;!N#0;               
     \`lD\$88Q8v*P\$QQQW=\` \`uOQ8|               
     \`*VD8Q888Q88DKL!   \`H?c?x               
    -^rZ@@8g88888~      w=|r a,              
   -^xB@##B888880.     v( V= .q              
  -^!d@#88QQ8888a     =z  S.  *}             
\`~*<-^Q########W:    .S   d    s:            
  .  VBQQdPwb8QQn\`   P-   b    \`A            
     ;KW6h^ ?Wa}(,  z!   -K     >n           
      x^^\`    -v**\`(x   \`vq_     z:          
     .v^_      <*~=8nseXyAP1zaaahV\$          
     ~*,       *^\"S.\`\`\`\` V~       <n         
    _}*       .n|G-      P-        z=        
    !e%]-     ,l8K~      -         \`Z\`       
       \`       ,?                   =^        
       
                       @cyber${red}X${cyan}pertise
                              
Get all possible passive subdomains
${end}"
Usage() {
    printf "%b\n" "
# ${bold}${blue}Options${end}:
    -d, --domain       - Domain To Enumerate (Required)
    -l, --list         - File containing list of domains to enumerate
    -o, --output       - Output directory (Default: ~/HUNT/<DOMAIN>)
    -s, --silent       - Silent mode (Only show results)
    -r, --resolve      - Resolve live subdomains
    -t, --thread       - Threads for resolution (Default: 40)
    -p, --parallel     - Run tools in parallel
    -h, --help         - Show help
    -v, --version      - Show version
# ${bold}${blue}Examples${end}:
    $PRG -d example.com
    $PRG -d example.com -p -r
    $PRG -l domains.txt -o /custom/path
"
    exit 1
}
check_tool() {
    command -v "$1" >/dev/null 2>&1 || echo -e "${red}[-] Warning: $1 is not installed! Skipping related tasks.${end}"
}
create_directories() {
    echo -e "${blue}[+] Creating directory structure...${end}"
    mkdir -p "${output_dir}/subs" || { echo -e "${red}[-] Failed to create directory: ${output_dir}${end}"; exit 1; }
}
count_results() {
    local tool=$1
    local file=$2
    if [[ -f "$file" ]]; then
        local count=$(wc -l < "$file")
        echo -e "${bold}[*] ${tool}${end}: ${count}"
    fi
}
run_assetfinder() {
    check_tool "assetfinder" || return
    local tmpfile="${output_dir}/subs/tmp-asset.txt"
    assetfinder -subs-only "$domain" > "$tmpfile"
    count_results "Assetfinder" "$tmpfile"
}
run_subfinder() {
    check_tool "subfinder" || return
    local tmpfile="${output_dir}/subs/tmp-subfinder.txt"
    subfinder -d "$domain" -silent -all -t 100 -o "$tmpfile" >/dev/null
    count_results "Subfinder" "$tmpfile"
}
run_findomain() {
    check_tool "findomain" || return
    local tmpfile="${output_dir}/subs/tmp-findo.txt"
    findomain -t "$domain" -q -u "$tmpfile" >/dev/null
    count_results "Findomain" "$tmpfile"
}
run_sublist3r() {
    check_tool "sublist3r" || return
    local tmpfile="${output_dir}/subs/tmp-sublist3r.txt"
    sublist3r -d "$domain" -n -t 100 -o "$tmpfile" >/dev/null
    count_results "Sublist3r" "$tmpfile"
}
run_crtsh() {
    check_tool "jq" || return
    local tmpfile="${output_dir}/subs/tmp-crt.txt"
    curl -s "https://crt.sh/?o=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' >>  "$tmpfile"
    #curl -s "https://crt.sh/?o=%.$domain&output=json" | jq -r '.[].common_name' | grep -v '*' | sort | uniq > "$tmpfile"
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | grep -v '*' | sort | uniq >> "$tmpfile"
    count_results "CRT.SH" "$tmpfile"
}
run_anubis() {
    check_tool "curl" || return
    local tmpfile="${output_dir}/subs/tmp-anubis.txt"
    curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u > "$tmpfile"
    count_results "Anubis" "$tmpfile"
}
run_rapiddns() {
    check_tool "curl" || return
    local tmpfile="${output_dir}/subs/tmp-rapid.txt"
    curl -s "https://rapiddns.io/subdomain/$domain?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' > "$tmpfile"
    count_results "RapidDNS" "$tmpfile"
}
run_wayback() {
    check_tool "curl" || return
    local tmpfile="${output_dir}/subs/tmp-wayback.txt"
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > "$tmpfile"
    count_results "Wayback" "$tmpfile"
}
run_abuseipdb() {
    check_tool "curl" || return
    local tmpfile="${output_dir}/subs/tmp-abuseipdb.txt"
    curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: firefox" -b "abuseipdb_session=" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" | sort -u > "$tmpfile"
    count_results "AbuseIPDB" "$tmpfile"
}
run_amass() {
    check_tool "amass" || return
    local tmpfile="${output_dir}/subs/tmp-amass.txt"
    amass enum -passive -norecursive -noalts -d "$domain" -o "$tmpfile" >/dev/null
    count_results "Amass" "$tmpfile"
}
resolve_subdomains() {
    check_tool "httprobe" || return
    echo -e "${blue}[+] Resolving live subdomains...${end}"
    httprobe -c "$thread" < "${output_dir}/subs.txt" > "${output_dir}/resolved.txt"
    echo -e "${green}[+] Resolved: $(wc -l < "${output_dir}/resolved.txt")${end}"
}
process_results() {
    echo -e "${blue}[+] Aggregating results...${end}"
    cat "${output_dir}/subs"/tmp-*.txt 2>/dev/null | sort -u > "${output_dir}/subs.txt"
    rm -f "${output_dir}/subs"/tmp-*.txt
    echo -e "${green}[+] Total unique subdomains: $(wc -l < "${output_dir}/subs.txt")${end}"
}
enumerate_domain() {
    domain=$1
    output_dir="$2"
    echo -e "${blue}[+] Enumerating subdomains for: $domain${end}"
    create_directories
    rm -f "${output_dir}/subs"/tmp-*.txt
    if [[ "$parallel" == True ]]; then
        # Export functions and variables for parallel execution
        export -f run_assetfinder run_subfinder run_findomain run_sublist3r run_crtsh run_anubis run_rapiddns run_wayback run_abuseipdb run_amass count_results check_tool
        export output_dir domain bold end red green blue cyan
        parallel --will-cite --halt soon,fail=1 ::: \
            run_assetfinder \
            run_subfinder \
            run_findomain \
            run_sublist3r \
            run_crtsh \
            run_anubis \
            run_rapiddns \
            run_wayback \
            run_abuseipdb \
            run_amass
    else
        run_assetfinder
        run_subfinder
        run_findomain
        run_sublist3r
        run_crtsh
        run_anubis
        run_rapiddns
        run_wayback
        run_abuseipdb
        run_amass
    fi
    process_results
    [[ "$resolve" == True ]] && resolve_subdomains
    echo -e "${green}[+] Results saved to: ${output_dir}/subs.txt${end}"
}
Main() {
    # Check dependencies (non-blocking)
    check_tool "assetfinder"
    check_tool "subfinder"
    check_tool "findomain"
    check_tool "sublist3r"
    check_tool "curl"
    check_tool "jq"
    check_tool "httprobe"
    check_tool "amass"

    if [[ -n "$domain_file" ]]; then
        # Process domains from file
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            output_dir="${HOME}/HUNT/${domain}"
            enumerate_domain "$domain" "$output_dir"
        done < "$domain_file"
    elif [[ -n "$domain" ]]; then
        # Process single domain
        output_dir="${HOME}/HUNT/${domain}"
        enumerate_domain "$domain" "$output_dir"
    else
        echo -e "${red}[-] Either -d/--domain or -l/--list must be provided!${end}"
        Usage
    fi
}
# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) domain="$2"; shift ;;
        -l|--list) domain_file="$2"; shift ;;
        -o|--output) output_dir="$2"; shift ;;
        -s|--silent) silent=True ;;
        -r|--resolve) resolve=True ;;
        -t|--thread) thread="$2"; shift ;;
        -p|--parallel) parallel=True ;;
        -h|--help) Usage ;;
        -v|--version) echo "$VERSION"; exit 0 ;;
        *) echo -e "${red}[-] Invalid option: $1${end}"; Usage ;;
    esac
    shift
done
# Set defaults
[[ -z "$thread" ]] && thread=40
[[ -z "$domain" && -z "$domain_file" ]] && { echo -e "${red}[-] Either -d/--domain or -l/--list must be provided!${end}"; Usage; }
Main
