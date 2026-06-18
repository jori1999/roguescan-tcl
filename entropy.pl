#!/usr/bin/env perl
# entropy.pl - Compute Shannon entropy for file blocks
# Usage: entropy.pl <file>
# Output: block N: entropy X.XX  (for each 4096-byte block)
#         file entropy: X.XX

use strict;
use warnings;
use POSIX qw(ceil);

my $path = shift or die "Usage: entropy.pl <file>\n";
open(my $fh, '<:raw', $path) or die "Cannot open $path: $!\n";
my $block_size = 4096;
my $block_num = 0;

# Read file in blocks
while (1) {
    my $buf;
    my $n = read($fh, $buf, $block_size);
    last if !$n;

    my @bytes = unpack('C*', $buf);
    my $len = scalar @bytes;
    next if $len < 256;

    # Count byte frequencies
    my %counts;
    $counts{$_}++ for @bytes;

    # Shannon entropy
    my $entropy = 0;
    for my $cnt (values %counts) {
        my $p = $cnt / $len;
        $entropy -= $p * log($p) / log(2) if $p > 0;
    }

    if ($entropy > 7.0) {
        printf "block %d: entropy %.4f\n", $block_num, $entropy;
    }
    $block_num++;
}

# Overall file entropy
seek($fh, 0, 0);
my @all_bytes = unpack('C*', do { local $/; <$fh> });
close($fh);

my $total = scalar @all_bytes;
if ($total >= 256) {
    my %counts;
    $counts{$_}++ for @all_bytes;
    my $entropy = 0;
    for my $cnt (values %counts) {
        my $p = $cnt / $total;
        $entropy -= $p * log($p) / log(2) if $p > 0;
    }
    printf "file entropy: %.4f\n", $entropy;
}
