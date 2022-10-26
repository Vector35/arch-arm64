#!/opt/local/bin/zsh
declare -A known_ranges
known_ranges=(
[A64]="1143-2013"
[SIMD]="2016-2943"
[SVE]="2945-4503"
[SME]="4505-4591"
)

declare -a PAGE_RANGE
args=($@)
# print -l ARGS: $args
for arg in $args
do
    if [[ ${arg[1]} == "-" ]]; then
        key=${arg:1}
        # print KEY: $key
        if [[ ${key} =~ "a|all|ALL" ]]; then
            PAGE_RANGE=${(v)known_ranges}
            args[${args[(i)$arg]}]=()
        # if [[ ${known_ranges[(i)$key]} == "$key"]]; then
        elif [[ ${(k)known_ranges} =~ $key && ${PAGE_RANGE[(i)${known_ranges[$key]}]} -gt ${#PAGE_RANGE} ]]; then
            PAGE_RANGE+=(${known_ranges[$key]})
            args[${args[(i)$arg]}]=()
        fi
    fi
    # print -l NEW_ARGS: $arg // $args
done
# print -l FINAL_ARGS: $args "${(*)args}"
PR=""
if [[ ${(*)PAGE_RANGE} != "" ]]; then declare -a PR ; PR=($(print -l $PAGE_RANGE | tr ' ' '\n' | sort -g)); PR="--page-range=${(*)PR// /,}"; fi
# print -l PAGE_RANGE: $PAGE_RANGE $PR

pdfgrep $PR -nP $args ~/Documents/arch/arm/DDI0487H_a_a-profile_architecture_reference_manual.pdf

# pdfgrep --page-range=1143-2013,2016-2943,2945-4503,4505-4591 -nP 'LDR' ~/Documents/arch/arm/DDI0487H_a_a-profile_architecture_reference_manual.pdf