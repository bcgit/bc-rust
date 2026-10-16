#!/bin/bash

get_cloc_lines_comments=""
get_cloc_lines_code=""
get_cloc_stats_for_files() {
  files=$1

  get_cloc_lines_comments="0"
  get_cloc_lines_code="0"

  while IFS="," read num_files lang blank comment code
  do
    get_cloc_lines_comments=$comment
    get_cloc_lines_code=$code
  done < <(cloc --csv --quiet $files | grep Rust &2>/dev/null)
}

get_docstring_lines=""
get_unwraps=""
get_errs=""
get_unsafes=""
get_docstring_and_errors_for_files() {
  files=$1

  total_unwraps="0"
  total_errs="0"
  total_unsafes="0"
  total_docstrings="0"
  for file in $1; do
    unwraps=$(cat $file| grep -o ".unwrap()" | wc -l)
    total_unwraps=$((total_unwraps + unwraps))

    errs=$(cat $file| grep -o "Err(" | wc -l)
    total_errs=$((total_errs + errs))

    unsafes=$(cat $file| grep -oE "unsafe (\{|fn|impl|trait)" | wc -l)
    total_unsafes=$((total_unsafes + unsafes))

    docstring_lines1=$(cat $file| grep -o "^//!" | wc -l)
    docstring_lines2=$(cat $file| grep -o "///" | wc -l)
    total_docstrings=$((total_docstrings + docstring_lines1 + docstring_lines2))
  done

  get_unwraps=$total_unwraps
  get_errs=$total_errs
  get_unsafes=$total_unsafes
  get_docstring_lines=$total_docstrings
}

crate_code_lines=""
crate_docstring_lines=""
crate_test_lines=""
crate_code_unwraps=""
crate_code_errs=""
crate_test_unwraps=""
analyze_crate() {
  cratedir=$1

  # Assumption: test files contain no meaningful volume of comments
  # Assumption: test code is all in the */test folder

  if [[ -d $cratedir/src ]]; then
    get_cloc_stats_for_files "$(find $cratedir/src -name "*.rs" &2>/dev/null)"
    code_code=$get_cloc_lines_code
#    code_comments=$get_cloc_lines_comments

    get_docstring_and_errors_for_files "$(find $cratedir/src -name "*.rs" &2>/dev/null)"
    code_docstring_lines=$get_docstring_lines
    code_unwraps=$get_unwraps
    code_errs=$get_errs
    code_unsafes=$get_unsafes
  else
    code_code="0"
    code_docstring_lines="0"
    code_unwraps="0"
    code_errs="0"
    code_unsafes="0"
  fi

  if [[ -d $cratedir/tests ]]; then
    get_cloc_stats_for_files "$(find $cratedir/tests -name "*.rs" &2>/dev/null)"
    tests_code=$get_cloc_lines_code

    get_docstring_and_errors_for_files "$(find $cratedir/tests -name "*.rs" &2>/dev/null)"
    tests_unwraps=$get_unwraps
  else
    tests_code="0"
    tests_unwraps="0"
  fi

  echo
  echo $(basename $cratedir)":"
  echo "  code lines: $code_code"
  echo "  docstring lines: $code_docstring_lines"
  test_ratio=$(echo "scale=2; $tests_code/$code_code" | bc)
  echo "  test lines: $tests_code ($test_ratio test ratio)" # todo "(X% of code)"
  echo "  fallibility:"
  echo "    unwraps in core code: $code_unwraps"
  echo "    Err() in core code: $code_errs"
  echo "    unwraps in test code: $tests_unwraps"
  echo "  unsafe blocks/fns/impls in core code: $code_unsafes"

  # Return values
  crate_code_lines=$code_code
  crate_docstring_lines=$code_docstring_lines
  crate_test_lines=$tests_code
  crate_code_unwraps=$code_unwraps
  crate_code_errs=$code_errs
  crate_test_unwraps=$tests_unwraps
  crate_code_unsafes=$code_unsafes
}

analyze_subcrates() {
  subcratedirs=$1


  total_code_lines="0"
  total_docstring_lines="0"
  total_test_lines="0"
  total_code_unwraps="0"
  total_code_errs="0"
  total_test_unwraps="0"
  total_code_unsafes="0"
  for subcrate in $subcratedirs;
  do
    analyze_crate $subcrate


  total_code_lines=$(( total_code_lines + crate_code_lines ))
  total_docstring_lines=$(( total_docstring_lines + crate_docstring_lines ))
  total_test_lines=$(( total_test_lines + crate_test_lines ))
  total_code_unwraps=$(( total_code_unwraps + crate_code_unwraps ))
  total_code_errs=$(( total_code_errs + crate_code_errs ))
  total_test_unwraps=$(( total_test_unwraps + crate_test_unwraps ))
  total_code_unsafes=$(( total_code_unsafes + crate_code_unsafes ))
  done

  echo
  echo
  echo "TOTALS:"
  echo "  code lines: $total_code_lines"
  echo "  docstring lines: $total_docstring_lines"
  test_ratio=$(echo "scale=2; $total_test_lines/$total_code_lines" | bc)
  echo "  test lines: $total_test_lines ($test_ratio test ratio)" # todo "(X% of code)"
  echo "  fallibility:"
  echo "    unwraps in core code: $total_code_unwraps"
  echo "    Err() in core code: $total_code_errs"
  echo "    unwraps in test code: $total_test_unwraps"
  echo "  unsafe blocks/fns/impls in core code: $total_code_unsafes"
}


main() {
  dirtoscan=$1

  # build a list of sub-crates (as subdir with a cargo.toml)
  subcratedirs=$(find $dirtoscan -maxdepth 2 -type f -iname "cargo.toml" -exec dirname {} \;)

  # print out the list we found
  if [[ ! -z "${subcratedirs// }" ]]; then
    echo "Subcrates found: "
    for subcrate in $subcratedirs; do
      echo -n `basename $subcrate`", "
    done
    echo
  else
    echo "No subcrates found"
    exit 0
  fi

  analyze_subcrates "$subcratedirs"

}


main $1