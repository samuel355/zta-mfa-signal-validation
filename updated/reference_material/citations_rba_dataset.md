# Citations — RBA (Risk-Based Authentication) Dataset

Added as a supplementary data source for the Spoofing STRIDE category (real
`Is Attack IP` / `Is Account Takeover` ground truth), alongside CIC-IDS2018
which remains the primary source for the other five STRIDE categories.

## Primary dataset publication

Wiefling, S., Jørgensen, P. R., Thunem, S., & Lo Iacono, L. (2022).
Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication
on a Real-World Large-Scale Online Service. *ACM Transactions on Privacy and
Security*, 25(3). https://doi.org/10.1145/3546069

```bibtex
@article{Wiefling_Pump_2022,
  author  = {Wiefling, Stephan and Jørgensen, Paul René and Thunem, Sigurd and Lo Iacono, Luigi},
  title   = {Pump {Up} {Password} {Security}! {Evaluating} and {Enhancing} {Risk}-{Based} {Authentication} on a {Real}-{World} {Large}-{Scale} {Online} {Service}},
  journal = {{ACM} {Transactions} on {Privacy} and {Security}},
  doi     = {10.1145/3546069},
  publisher = {ACM},
  year    = {2022}
}
```

## Dataset itself (cite separately from the paper — has its own DOI)

Wiefling, S., Jørgensen, P. R., Thunem, S., & Lo Iacono, L. (2022).
Login Data Set for Risk-Based Authentication [Data set]. Zenodo.
https://doi.org/10.5281/zenodo.6782156 (CC-BY 4.0)

```bibtex
@dataset{Wiefling_RBA_Dataset_2022,
  author    = {Wiefling, Stephan and Jørgensen, Paul René and Thunem, Sigurd and Lo Iacono, Luigi},
  title     = {{Login Data Set for Risk-Based Authentication}},
  year      = {2022},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.6782156},
  url       = {https://zenodo.org/records/6782156}
}
```

## Follow-up validation paper (currency evidence — shows the dataset/methodology is still actively used)

Wiefling, S., Iacono, L. L., & Dürmuth, M. (2023). Evaluation of Real-World
Risk-Based Authentication at Online Services Revisited: Complexity Wins.
*European Symposium on Usable Security (EuroUSEC '23)*.
https://doi.org/10.1145/3600160.3605024

```bibtex
@inproceedings{Wiefling_Revisited_2023,
  author    = {Wiefling, Stephan and Lo Iacono, Luigi and Dürmuth, Markus},
  title     = {Evaluation of {Real}-{World} {Risk}-{Based} {Authentication} at {Online} {Services} {Revisited}: {Complexity} {Wins}},
  booktitle = {Proceedings of the 2023 European Symposium on Usable Security},
  doi       = {10.1145/3600160.3605024},
  year      = {2023}
}
```

## Recent citing work (2024–2025, supports the "still current" claim in Chapter 2/3)

- A 2024 machine-learning classification study benchmarking server-side login-risk
  classifiers against Wiefling et al.'s real-world results on this dataset.
- "That's not you! Applying Neural Networks to Risk-Based Authentication to
  Detect Suspicious Logins" — Proceedings of the 18th ACM Workshop on
  Artificial Intelligence and Security (AISec '25), co-located with CCS 2025.
  https://doi.org/10.1145/3733799.3762970

```bibtex
@inproceedings{ThatsNotYou_AISec_2025,
  title     = {That's not you! {Applying} {Neural} {Networks} to {Risk}-{Based} {Authentication} to {Detect} {Suspicious} {Logins}},
  booktitle = {Proceedings of the 18th ACM Workshop on Artificial Intelligence and Security},
  doi       = {10.1145/3733799.3762970},
  year      = {2025}
}
```

## Important framing note for the methodology section

The RBA README itself states: *"The feature values are plausible, but still
totally artificial. Therefore, you should NOT use this data set in productive
systems, e.g., intrusion detection systems."* The publisher synthesized the
released version from real production data for privacy reasons — it preserves
real-world statistical properties (validated in the original paper) but is not
raw production traffic. This should be disclosed the same way CIC-IDS2018's
own limitations are disclosed — neither dataset is claimed as perfectly
representative of live traffic, and this is standard/expected practice in the
field, not a weakness specific to this choice.

## Schema actually used (confirmed by extracting the dataset directly)

`index, Login Timestamp, User ID, Round-Trip Time [ms], IP Address, Country,
Region, City, ASN, User Agent String, Browser Name and Version, OS Name and
Version, Device Type, Login Successful, Is Attack IP, Is Account Takeover`

Region/City are redacted in the public release (`-` placeholder) — only
Country-level geolocation is usable, which is why a country-centroid lookup
(rather than precise lat/lon) is used for the GPS-based validation checks.
