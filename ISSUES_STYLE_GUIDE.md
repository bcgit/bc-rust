# Issues style guide

## Sub-issues

When an issue requires a large amount of time or code changes to complete, it may be convenient for a contributor to break it up into distinct sub-issues, which can each be addressed by a separate pull request.
This avoids reviewers managing very large PRs, or submitters needing to frequently resolve merge conflicts in their branches.
However, not all large changes can be separated into logically distinct and separately testable sub-issues - instead, consider breaking your branch into separate commits with clear commit messages, so that reviewers can inspect these changes in logical steps.

Breaking up an issue into sub-issues is project-management work, so please keep your fellow contributors in mind when doing so.
This process requires following a mandatory sub-issue description template, to ensure that the parent issue is fully completed and that sub-issues are clear and distinct enough for others to comprehend.
If you would like to break up issue into sub-issues, please follow these requirements:

* The series of sub-issues, when completed, must entirely complete the original task (do not create a series of sub-issues that leaves any part of the parent issue unfinished)
* Each sub-issue must be independent enough to be submittable in a unique pull request, and must not cause any regressions in existing behavior if submitted
* Each sub-issue must be able to be validated independently based on the Acceptance Criteria (see template below) listed in the sub-issue
* Individual sub-issues are presumed to be ordered, and dependent on previous sub-issues, unless marked "parallelizable" in the subject line. Please create your sub-issues in the order you intend them to be completed.
* If a sub-issue is distinct enough from the others that it can be worked on in parallel, and you'd like help in completing it, please mark it as "parallelizable" in the subject line!

### Sub-issue template (mandatory):

Name:

describe this individual contribution, add "parallelizable" if it has no dependencies on other tasks.

Summary:

Describe exactly which result(s) of the parent task should be completed here, rather than in other sub-issues. Keep it brief and don't restate redundant details that are included in the parent task.

Scope:

If possible, describe which parts of the repo and/or behavior are expected to be impacted by this change, or potentially which parts should not be impacted.
This is to help reviewers notice mistaken commits, or (if completed by someone else) unexpected approaches that may require extra attention for consistency with the other sub-issues.

Acceptance Criteria:

A checklist of items for reviewers to validate. These should include both the new functionality/fixes expected to be completed, as well as any related possible regressions around existing behavior that should be checked for.
- [ ] for example, cargo test --workspace should pass

## Issues

No specific requirements are mandated for issues, but the following template may help in writing an issue description.

### Issue template (optional)

Name:

Describe the problem or goal of the desired change

Summary:

Expand on the issue name, giving a one or two sentence description of the problem or desired change.

Details:

Add all pertinent details about the issue that you can. When reporting an issue, include all the steps you use to reproduce it, and the environment that reproduced it.
When requesting a feature improvement, please describe the goal you're hoping to achieve, and other alternative approaches that you have considered.
Consider providing links to information that will help contributors better understand the issue or goal.

Scope: (optional)

If you're suggesting a change regarding parts of the repo that you have some understanding of, consider whether you can describe which parts of the repo and/or behavior are expected to be
impacted by this change, or which parts you think should not be impacted. This may add context that helps guide contributors more quickly to a solution, or help reviewers notice mistakes
or unexpected approaches in a pull request addressing this issue.

Acceptance Criteria: (optional)

If you're sufficiently familiar with this issue, and have a sense of exactly what should or should not be done to resolve this issue, start a checklist of items here for contributors to work towards
and reviewers to validate. These should include both the new functionality/fixes expected to be completed, as well as any related possible regressions around existing behavior that should be checked for.
- [ ] for example, cargo test --workspace should pass
