# CI

Continuous integration jobs are common across all mango repositories.
The common CI lives here: <TBD>

## Automatic dependency updator

We have a weekly running job, that makes use of `update-properties` goal, to attempt and upgrade any dependencies possible.
Examples on what restrictions we can put are found here: https://www.mojohaus.org/versions/versions-maven-plugin/examples/update-properties.html
Main restriction to using this, is that the versions MUST be defined as properties.
The dependency updator and how it works will be fully documented in another place and link to that will be added here.

Forcing tomcat-embed-el.version, commons-text.version, to be fixed until a solution is added to exclude interesting versions.
By interesting is meant this:
${tomcat-embed-el.version} from 9.0.62 to 11.0.0-M10
${commons-text.version} from 1.10.0 to 1.10.0.redhat-00001

Not sure why the above force did not work in the upgrador. Needs further investigation. See: <TBD>

Updating this just for a bb PR test