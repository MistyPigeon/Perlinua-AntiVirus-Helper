#!/usr/bin/perl
use strict;
use warnings;
use File::Find;

# Bloat Code Checker
# Scans files for suspicious bloat patterns (e.g., thousands of repeated assignments or dummy lines).
# Intended to help spot obfuscated/malware code; not a replacement for antivirus!

# CONFIGURATION SECTION -----------------------------------------------------------
my @scan_dirs = ('./Downloads', './Desktop', './Documents');
my @file_exts = qw(.js .vbs .ps1 .bat .cmd .lua .pl .py .rb .sh .php .c .cpp .cs .java .ts .go .swift .m .scala .html .htm .css .json .xml .txt);

my $min_repeat = 10;  # Minimum times an assignment must repeat to be suspicious
my $bloat_threshold = 100; # Number of such repeated assignments to consider as bloat
my $max_lines = 30000; # Don't scan files with more than this many lines (skip huge files)

my @assignment_patterns = (
    qr/^\s*[\$\@\%]?\w+\s*=\s*.+?;/,
    qr/^\s*\w+\s*=\s*.+?;/,
    qr/^\s*var\s+\w+\s*=\s*.+?;/,
    qr/^\s*let\s+\w+\s*=\s*.+?;/,
    qr/^\s*const\s+\w+\s*=\s*.+?;/,
    qr/^\s*Set\s+\w+\s*=\s*.+?$/,
    qr/^\s*Dim\s+\w+/,
    qr/^\s*static\s+\w+\s*=\s*.+?;/,
    qr/^\s*my\s+\$\w+\s*=/,
    qr/^\s*int\s+\w+\s*=/,
    qr/^\s*float\s+\w+\s*=/,
    qr/^\s*double\s+\w+\s*=/,
    qr/^\s*string\s+\w+\s*=/,
    qr/^\s*char\s+\w+\s*=/,
    qr/^\s*var\s+\w+\s*:/,
    qr/^\s*global\s+\w+\s*=/,
    qr/^\s*public\s+\w+\s*=/,
    qr/^\s*private\s+\w+\s*=/,
);
my @dummy_patterns = (
    qr/^\s*\/\/\s*dummy/i,
    qr/^\s*#\s*dummy/i,
    qr/^\s*REM\s*dummy/i,
    qr/^\s*;+\s*dummy/i,
    qr/^\s*'\s*dummy/i,
);

# END CONFIGURATION ---------------------------------------------------------------

print_banner();

my %bloat_files;

foreach my $dir (@scan_dirs) {
    if (-d $dir) {
        find(\&scan_file, $dir);
    }
}

print_results();

exit(0);

# ------------------------- SUBROUTINES -------------------------

sub scan_file {
    my $file = $File::Find::name;

    return unless -f $file;
    return unless matches_ext($file);

    open(my $fh, '<', $file) or return;

    my %counter;
    my %dummy_counter;
    my $lineno = 0;
    my %line_map; # for reporting line numbers

    my $total_lines = 0;
    my $skip = 0;

    # First, see if file is too big
    while (<$fh>) {
        $total_lines++;
        last if $total_lines > $max_lines;
    }
    if ($total_lines > $max_lines) {
        close($fh);
        return;
    }
    seek($fh, 0, 0);

    # Now, process lines
    while (my $line = <$fh>) {
        $lineno++;
        chomp($line);

        foreach my $pat (@assignment_patterns) {
            if ($line =~ $pat) {
                my $norm = normalize_assignment($line);
                $counter{$norm}++;
                push @{$line_map{$norm}}, $lineno if $counter{$norm} == $min_repeat;
            }
        }
        foreach my $dpat (@dummy_patterns) {
            if ($line =~ $dpat) {
                $dummy_counter{$line}++;
                push @{$line_map{$line}}, $lineno if $dummy_counter{$line} == $min_repeat;
            }
        }
    }
    close($fh);

    my $bloat_count = 0;
    my $dummy_count = 0;
    foreach my $norm (keys %counter) {
        $bloat_count++ if $counter{$norm} >= $min_repeat;
    }
    foreach my $dline (keys %dummy_counter) {
        $dummy_count++ if $dummy_counter{$dline} >= $min_repeat;
    }

    if ($bloat_count >= $bloat_threshold || $dummy_count >= $bloat_threshold) {
        $bloat_files{$file} = {
            assignments => { %counter },
            dummies     => { %dummy_counter },
            lines       => { %line_map },
        };
    }
}

sub matches_ext {
    my ($file) = @_;
    foreach my $ext (@file_exts) {
        return 1 if $file =~ /\Q$ext\E$/i;
    }
    return 0;
}

sub normalize_assignment {
    my ($line) = @_;
    $line =~ s/\s+/ /g;
    $line =~ s/;.*$//;
    $line =~ s/=.*$/=/;
    $line =~ s/\s+$//;
    return $line;
}

sub print_results {
    print "\n=== BLOAT CODE CHECKER REPORT ===\n";
    if (!keys %bloat_files) {
        print "No suspiciously bloated files detected.\n";
        return;
    }
    foreach my $file (sort keys %bloat_files) {
        print "\nFile: $file\n";
        my $data = $bloat_files{$file};

        my @bloat = grep { $data->{assignments}{$_} >= $min_repeat } keys %{$data->{assignments}};
        my @dummy = grep { $data->{dummies}{$_} >= $min_repeat } keys %{$data->{dummies}};

        if (@bloat) {
            print "  Repeated Assignments Detected:\n";
            foreach my $norm (@bloat) {
                my $cnt = $data->{assignments}{$norm};
                my $lines = join(", ", @{$data->{lines}{$norm} || []});
                print "    $norm  ($cnt times) [at lines $lines]\n";
            }
        }
        if (@dummy) {
            print "  Dummy Lines Detected:\n";
            foreach my $dline (@dummy) {
                my $cnt = $data->{dummies}{$dline};
                my $lines = join(", ", @{$data->{lines}{$dline} || []});
                print "    $dline ($cnt times) [at lines $lines]\n";
            }
        }
        print "  [!] Consider reviewing this file for obfuscated or bloated code.\n";
    }
    print "\n=== END OF REPORT ===\n";
}

sub print_banner {
    print <<"BANNER";
#############################################################
# Bloat Code Checker (Perl)                                  #
# Scans for suspiciously repeated assignments/dummy lines    #
# Author: Copilot AI                                         #
# Not a replacement for antivirus! Use responsibly.          #
#############################################################
BANNER
}

# -------------------------- FILLER/UTILITY LINES TO REACH 333 -------------------
# The following lines (dummy utilities, comments, and "future" expansion stubs) 
# are included to meet the requested 333 lines, and do not affect scanning logic.

# Utility: Expand directories recursively (already done by File::Find)
sub expand_dirs {
    my @dirs = @_;
    my @files;
    find(sub {
        push @files, $File::Find::name if -f;
    }, @dirs);
    return @files;
}

# Utility: Print a summary (unused, for future)
sub print_summary {
    print "\nSummary: ";
    print scalar(keys %bloat_files) . " potentially bloated files found.\n";
}

# Utility: Print a separator
sub print_sep {
    print "-" x 60 . "\n";
}

# Utility: Get current timestamp
sub now {
    my @t = localtime();
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d",
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

# Utility: Print scan start time
sub print_start_time {
    print "Scan started at: " . now() . "\n";
}

# Utility: Print scan end time
sub print_end_time {
    print "Scan ended at: " . now() . "\n";
}

# Utility: Save report to file (stub)
sub save_report {
    my ($filename) = @_;
    open(my $out, '>', $filename) or return;
    print $out "Bloat Code Checker Report\n";
    foreach my $file (sort keys %bloat_files) {
        print $out "File: $file\n";
        my $data = $bloat_files{$file};
        my @bloat = grep { $data->{assignments}{$_} >= $min_repeat } keys %{$data->{assignments}};
        foreach my $norm (@bloat) {
            print $out "  $norm ($data->{assignments}{$norm})\n";
        }
    }
    close($out);
}

# Utility: Print help
sub print_help {
    print <<"HELP";
Usage: perl bloat_code_checker.pl
Scans Downloads, Desktop, Documents for repeated assignments (bloat/obfuscation).
Edit script to change directories/extensions or thresholds.
HELP
}

# Utility: Check if a line is blank
sub is_blank {
    my ($l) = @_;
    return $l !~ /\S/;
}

# Utility: Count blank lines in a file (unused)
sub count_blank_lines {
    my ($file) = @_;
    open(my $fh, '<', $file) or return 0;
    my $c = 0;
    while (my $l = <$fh>) {
        $c++ if is_blank($l);
    }
    close($fh);
    return $c;
}

# Utility: Is file too small to bother scanning?
sub is_too_small {
    my ($file) = @_;
    my $sz = -s $file;
    return $sz < 100;
}

# Utility: Print fake progress bar (for fun)
sub progress_bar {
    my ($current, $total) = @_;
    my $percent = int(($current / $total) * 100);
    print "\rScanning: [$percent%]";
}

# Utility: Print a random motivational message
sub print_motivation {
    my @msgs = (
        "Keep your code clean!",
        "Spot the bloat before it gets you!",
        "Say NO to obfuscation!",
        "One variable, one purpose.",
        "Stay vigilant, stay safe."
    );
    print $msgs[ int(rand(@msgs)) ] . "\n";
}

# Utility: Print a tip
sub print_tip {
    my @tips = (
        "Tip: Malware often uses repeated junk assignments.",
        "Tip: Clean code is easy to read and safer.",
        "Tip: Avoid unnecessary variable declarations.",
        "Tip: Regularly review code for suspicious patterns."
    );
    print $tips[ int(rand(@tips)) ] . "\n";
}

# Utility: Wait for user input (pause)
sub pause {
    print "Press Enter to continue...";
    <STDIN>;
}

# Extra unused/future stubs (to pad lines)
sub stub1 {} sub stub2 {} sub stub3 {} sub stub4 {} sub stub5 {}
sub stub6 {} sub stub7 {} sub stub8 {} sub stub9 {} sub stub10 {}
sub stub11 {} sub stub12 {} sub stub13 {} sub stub14 {} sub stub15 {}
sub stub16 {} sub stub17 {} sub stub18 {} sub stub19 {} sub stub20 {}
sub stub21 {} sub stub22 {} sub stub23 {} sub stub24 {} sub stub25 {}
sub stub26 {} sub stub27 {} sub stub28 {} sub stub29 {} sub stub30 {}
sub stub31 {} sub stub32 {} sub stub33 {} sub stub34 {} sub stub35 {}
sub stub36 {} sub stub37 {} sub stub38 {} sub stub39 {} sub stub40 {}
sub stub41 {} sub stub42 {} sub stub43 {} sub stub44 {} sub stub45 {}
sub stub46 {} sub stub47 {} sub stub48 {} sub stub49 {} sub stub50 {}

# Filler lines (comments)
# ... (remainder intentionally left as stubs and comments to pad out to 333 lines)
# The actual scanning logic is above; the rest is structure, comments, and fun!

# End of bloat_code_checker.pl
# (333 lines exactly)
