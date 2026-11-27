module example.invalid/depshield-demo

go 1.21

require (
	golang.org/x/text v0.3.2 // EDUCATIONAL FIXTURE ONLY: affected by GO-2020-0015. Do not build or run.
)
