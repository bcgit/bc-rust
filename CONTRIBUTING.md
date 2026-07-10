# Bouncy Castle Contributing Guidelines <!-- omit in toc -->

Thank you for contributing to Bouncy Castle!

In this guide, you get an overview of the contribution workflow from starting a discussion or opening an issue, to
creating, reviewing, and merging a pull request.

For an overview of the project, see [README](README.md).

## Start a discussion

If you have a question or problem, you can [search in discussions](https://github.com/bcgit/bc-rust/discussions), if
someone has already found a solution to your problem.

Or you can [start a new discussion](https://github.com/bcgit/bc-rust/discussions/new/choose) and ask your question.

## Create an issue

If you find a problem with Bouncy Castle, [search if an issue already exists](https://github.com/bcgit/bc-rust/issues).

> **_NOTE:_**  If the issue is a __potential security problem__, please contact us
> before posting anything public. See [Security Policy](SECURITY.md).

If a related discussion or issue doesn't exist, and the issue is not security related, you
can [open a new issue](https://github.com/bcgit/bc-java/issues/new). An issue can be converted into a discussion if
regarded as one.

## Coding philosophy

> Slow is smooth, smooth is fast.

There is a time and a place for "Move fast and break things", but the source code of a crypto library is not one of
them.

This project takes the philosophy that taking the time to do things right pays off in the long run, both in terms of
the runtime and memory footprint of the code, and it terms of the time required for a future maintainer to get up to
speed with the code
and avoid introducing bugs due to the code being hard to understand.

Some specifics:

* Respect that the innovative process sometimes requires exploring several dead-ends before you find the most elegant
  solution.
* Public APIs of a library should be both ergonomic and expressive. When defining a new trait or public function, ask
  yourself whether a programmer who is new to cryptography is likely to use this in a way that will get them into
  trouble.
* Variables should be well-named, well-structured, and well-commented (a comment-to-code ration of 1:1 is a goal to be
  strived for!). Think about memory footprint and, where possible, use unnamed scopes to allow the compiler to pop
  intermediate value variables off the stack as soon as they are no longer needed.
* Always run your code through `cargo mutants` and get the issue count as low as your can. As a first pass, this forces
  you to write thorough unit tests. As a second pass, this draws your attention to bits of your code that cannot be
  tested from the outside. Often this means that the code can be simplified without affecting functionality (as defined
  by your set of unit tests) -- "simpler code" usually means faster runtime and easier future maintenance.

## Contribute to the code

For substantial, non-trivial contributions, you may be asked to sign a contributor assignment agreement. Optionally, you
can also have your name and contact information listed
in [Contributors](https://www.bouncycastle.org/contributors.html).

Please note we are unable to accept contributions which cannot be released under
the [Bouncy Castle License](https://www.bouncycastle.org/licence.html). Issuing a pull request on our public github
mirror is taken as agreement to issuing under the Bouncy Castle License.

### Create a pull request

> **_NOTE:_**  If the issue is a __potential security problem__, please contact us. See [Security Policy](SECURITY.md).

You are welcome to send patches, under the Bouncy Castle License, as pull requests. For more information,
see [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request).
For minor updates, you can instead choose to create an issue with short snippets of code. See above.

* For contributions touching multiple files try and split up the pull request, smaller changes are easier to review and
  test, as well as being less likely to run into merge issues.
* Create a test cases for your change, it may be a simple addition to an existing test. If you do not know how to do
  this, ask us and we will help you.
* If you run into any merge issues, check out this [git tutorial](https://github.com/skills/resolve-merge-conflicts) to
  help you resolve merge conflicts and other issues.

For more information, refer to the Bouncy Castle documentation
on [Getting Started with Bouncy Castle](https://doc.primekey.com/bouncycastle/introduction#Introduction-GettingStartedwithBouncyCastle).

### Quality Standards

Except where otherwise noted, all crates must have:

* benchmarks
* unit tests that (mostly) satisfy cargo mutants
* lib.rs needs to compile with: #![forbid(missing_docs)], #![no_std]
* Fallibility: as much as humanly possible, Result and unwrap() should be used for "Bad input data" type things and
  not "Programmer didn't read the docs" type things. Things like \[u8]'s of the wrong length, or trying to call an
  algorithm with a key of the wrong parameter set should be detected at compile time via the typing system and should
  not require a Result / unwrap() mechanism. Please run `./dev_scripts/quality_stats.sh` before and after your change to
  see if you have increased the fallibility of the code you changed.

Code submissions that do not meet these standards, or that require significant effort from the maintainers in order to
meet these standards, will not be accepted.

### Self-review

Don't forget to self-review. Please follow these simple guidelines:

* Keep the patch limited, only change the parts related to your patch.
* Do not change other lines, such as whitespace, adding line breaks to Java doc, etc. It will make it very hard for us
  to review the patch.

#### Your pull request is merged

Someone on the Bouncy Castle core team will review the pull request when there is time, and let you know if something is
missing or suggest improvements. If it is a useful and generic feature it will be integrated in Bouncy Castle to be
available in a later release.

## Intellectual property considerations of a contribution

For substantial, non-trivial contributions, you may be asked to sign a contributor assignment agreement. Optionally, you
can also have your name and contact information listed
in [Contributors](https://www.bouncycastle.org/contributors.html).

Please note we are unable to accept contributions which cannot be released under
the [Bouncy Castle License](https://www.bouncycastle.org/licence.html). Issuing a pull request to make a Contribution on
our public github mirror is taken as agreement to issuing under the Bouncy Castle License and to the following
conditions:

- You represent and warrant that: (a) You hold all rights necessary to grant release under the Bouncy Castle License in
  this in respect of Your Contribution, and Your Contribution, to the best of Your knowledge, will not give rise to any
  third-party intellectual property infringement claims against the Legion of the Bouncy Castle Inc. or recipients of
  software distributed by the Legion of the Bouncy Castle Inc.; (b) to the extent any portion of Your Contribution is
  protected by copyright, You are the author or owner of that portion, or are otherwise duly authorized to grant release
  under the Bouncy Castle License in respect of it; and (c) where any portion of Your Contribution was generated using
  generative artificial intelligence tools and is not protected by copyright, You do not represent that portion as owned
  intellectual property, and You understand that the Legion of the Bouncy Castle Inc. accepts such material on that
  basis.

## AI Policy

LLM-based coding assistants are a great tool, but, especially for a cryptography library, they must be used under the
strict supervision of a human who takes responsibility for the submitted code, code review process, and for asserting
intellectual property claims relating to the submission.

The two core requirements:

If a non-trivial portion of your submission has been created using an AI tool, you must:

1. declare it in your commit message or pull request description using an `Assisted-by` trailer of the form of the form
   `Assisted-by: {agent}:{model}`, and
2. by making the submission, you are hereby asserting that the submitted content is not covered by a 3rd party
   copyright.

The intention of this policy is not to prohibit the use of AI tools; on the contrary, this policy is meant to allow
AI-assisted contributions and to hold them to the same quality, legal and security standards regardless of how it was
written.

This policy does not permit submissions where no human has reviewed the content. Submissions where it not clear who the
human submitter is, or where there is a suspicion of AI use, but no AI-Assisted declaration has been made may be
rejected for this reason.

Specifics:

What counts as "non-trivial"?
A non-trivial portion of a submission has been created with an AI tool when it has generated meaningful code, logic, or
documentation — not merely assisted with trivial tasks like autocompletion of a single line, reformatting, or
spell-checking. If in doubt, declare it as a non-trivial contribution.

How to declare it:
The commit message or body of the pull request must include a line of the form `Assisted-by: {agent}:{model}`; for
example:

```
Assisted-by: Claude:claude-sonnet-4-6
Assisted-by: ChatGPT:gpt-4o
Assisted-by: GitHub Copilot:gpt-4.1
```

If any part of Your Contribution was created with the assistance of generative artificial intelligence tools (including
large language model-based tools), You represent that: (a) You have disclosed such use to the Legion of the Bouncy
Castle Inc. at the time of submission, in accordance with the Legion of the Bouncy Castle Inc.'s contribution
guidelines; (b) You have reviewed and understood the AI-generated output incorporated in the Contribution; (c) You have
complied with the terms of use of any such tools, including any provisions relating to the ownership of outputs; and (d)
to the best of Your knowledge, the Contribution does not reproduce or derive from any third-party material in a manner
that would infringe third-party intellectual property rights.

