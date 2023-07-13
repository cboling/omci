# CG-Decoder

This is an example application that can be used to decode an OMCI message stream (ASCII text) that
is in a vendor that I worked with whose ONU would dump the messages it sent and received.

Hopefully it will provide other vendors or companies a basis to write their own OMCI decoders
to help out solving issues. Should you write one and wish to contribute, please file a issue on
this github project, or a pull request that contains your decoder and at least one sample
output to decode. I will do my best to add coverage for your format to my unit tests so that
things never go stale.

## Building

1. Update dependencies:   make mod-update # from base directory
2. Build code:            make cg-omci-decode # from base directory

## Running

./cg-omci-decode -input examples/cg-decode/cg-omci-sequence.omci.txt
